//! Outlook mailboxes (`.pst`, `.ost`): what a host's mail says, which strings
//! cannot give. A contact's address is not a sender, and drafts and sent items
//! are only found by reading the folders.
//!
//! Every message is an event, wherever its folder table says it is: the node
//! tree is walked, so an item dropped from a table still shows.

mod crypt;
mod ltp;
mod ndb;

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::Ts;
use crate::artifact::{Artifact, ParseOptions, Sink, Source, UnitReport};
use crate::event::{EventView, Field, Val};
use crate::id::{EventRef, FileKey};
use ltp::{PT_UNICODE, Props, Table};
use ndb::{Node, Reader, Store};

const CHANNEL: &str = "Mail";
const PROVIDER: &str = "Mail";
const EID_MESSAGE: u32 = 1;
const EID_ATTACHMENT: u32 = 2;
const EID_CONTACT: u32 = 3;
/// Node types, the low five bits of a node id.
const NT_FOLDER: u32 = 2;
const NT_MESSAGE: u32 = 4;
const NID_STORE: u32 = 0x21;
const NID_RECIPIENTS: u32 = 0x692;
const NID_ATTACHMENTS: u32 = 0x671;

const PR_SUBJECT: u16 = 0x0037;
const PR_CLASS: u16 = 0x001A;
const PR_CLIENT_SUBMIT: u16 = 0x0039;
const PR_SENT_NAME: u16 = 0x0042;
const PR_SENT_ADDRESS: u16 = 0x0065;
const PR_HEADERS: u16 = 0x007D;
const PR_SENDER_NAME: u16 = 0x0C1A;
const PR_SENDER_ADDRESS: u16 = 0x0C1F;
const PR_RECIPIENT_TYPE: u16 = 0x0C15;
const PR_DELIVERY: u16 = 0x0E06;
const PR_FLAGS: u16 = 0x0E07;
const PR_BODY: u16 = 0x1000;
const PR_RTF: u16 = 0x1009;
const PR_HTML: u16 = 0x1013;
const PR_MESSAGE_ID: u16 = 0x1035;
const PR_IN_REPLY_TO: u16 = 0x1042;
const PR_DISPLAY_NAME: u16 = 0x3001;
const PR_EMAIL: u16 = 0x3003;
const PR_CREATED: u16 = 0x3007;
const PR_MODIFIED: u16 = 0x3008;
const PR_ATTACH_DATA: u16 = 0x3701;
const PR_ATTACH_NAME: u16 = 0x3704;
const PR_ATTACH_LONG_NAME: u16 = 0x3707;
const PR_ATTACH_METHOD: u16 = 0x3705;
const PR_ATTACH_MIME: u16 = 0x370E;
const PR_SMTP: u16 = 0x39FE;
const PR_SENDER_SMTP: u16 = 0x5D01;
const PR_SENT_SMTP: u16 = 0x5D02;
const MSGFLAG_UNSENT: u64 = 8;
/// Per message: more says nothing new, and the body still holds them.
const MAX_URLS: usize = 1000;

pub struct MailArtifact;

impl Artifact for MailArtifact {
    fn name(&self) -> &'static str {
        "mail"
    }
    fn sniff(&self, head: &[u8]) -> bool {
        head.starts_with(b"!BDN")
    }
    fn matches_name(&self, path: &Path) -> bool {
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("pst") || e.eq_ignore_ascii_case("ost"))
    }
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>> {
        Ok(Arc::new(MailSource::open(path, opts)?))
    }
}

pub struct MailSource {
    path: PathBuf,
    key: FileKey,
    len: u64,
    store: Store,
    host: String,
    user: String,
    warnings: Vec<String>,
}

/// The profile holding the mailbox (`Users\<name>\AppData\...`).
fn user_of(path: &Path) -> String {
    let parts: Vec<_> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect();
    let appdata = parts
        .iter()
        .rposition(|p| p.eq_ignore_ascii_case("AppData"));
    match appdata {
        Some(i) if i >= 2 && parts[i - 2].eq_ignore_ascii_case("Users") => parts[i - 1].to_string(),
        _ => String::new(),
    }
}

impl MailSource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<MailSource> {
        let store = Store::open(path)?;
        let len = std::fs::metadata(path)?.len();
        let key = match opts.key {
            Some(k) => k,
            None => FileKey::of_file(path)?,
        };
        let mut warnings = Vec::new();
        if store.bad_pages > 0 {
            warnings.push(format!(
                "{}: {} unreadable index pages, some items are missing",
                path.display(),
                store.bad_pages
            ));
        }
        Ok(MailSource {
            path: path.to_path_buf(),
            key,
            len,
            store,
            host: crate::registry::computer_for(path).unwrap_or_default(),
            user: user_of(path),
            warnings,
        })
    }
}

struct Rec {
    eid: u32,
    ts: Ts,
    fields: Vec<Field<'static>>,
}

fn field(name: &'static str, value: Val<'static>) -> Field<'static> {
    Field {
        name: Cow::Borrowed(name),
        value,
    }
}

impl Rec {
    fn new(eid: u32, ts: Ts) -> Rec {
        Rec {
            eid,
            ts,
            fields: Vec::new(),
        }
    }
    fn s(&mut self, name: &'static str, v: impl Into<String>) -> &mut Rec {
        let v = v.into();
        if !v.is_empty() {
            self.fields.push(field(name, Val::Str(Cow::Owned(v))));
        }
        self
    }
    fn opt(&mut self, name: &'static str, v: Option<String>) -> &mut Rec {
        if let Some(v) = v {
            self.s(name, v);
        }
        self
    }
    fn n(&mut self, name: &'static str, v: u64) -> &mut Rec {
        self.fields
            .push(field(name, Val::Num(Cow::Owned(v.to_string()))));
        self
    }
    fn time(&mut self, name: &'static str, v: Option<Ts>) -> &mut Rec {
        if let Some(t) = v {
            self.s(name, crate::registry::iso(t));
        }
        self
    }
    fn flag(&mut self, name: &'static str, v: bool) -> &mut Rec {
        if v {
            self.fields.push(field(name, Val::Bool(true)));
        }
        self
    }
}

/// A subject may start with `\x01` and a length: the prefix marker.
fn subject(p: &Props<'_, '_>) -> String {
    let s = p.text(PR_SUBJECT).unwrap_or_default();
    match s.strip_prefix('\u{1}') {
        Some(rest) => rest.chars().skip(1).collect(),
        None => s,
    }
}

fn entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        _ => {
            let n = name.strip_prefix('#')?;
            let code = match n.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => n.parse().ok()?,
            };
            char::from_u32(code)?
        }
    })
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest[1..]
            .find(';')
            .filter(|end| *end <= 10)
            .and_then(|end| Some((entity(&rest[1..end + 1])?, end)));
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &rest[end + 2..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Readable text of an HTML body. Links stay reachable through `Urls`.
fn html_text(html: &str) -> String {
    static NOISE: OnceLock<Regex> = OnceLock::new();
    static BREAK: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    static BLANK: OnceLock<Regex> = OnceLock::new();
    let re = |c: &'static OnceLock<Regex>, p: &str| -> &'static Regex {
        c.get_or_init(|| Regex::new(p).expect("valid regex"))
    };
    let t = re(
        &NOISE,
        r"(?is)<!--.*?-->|<head\b.*?</head>|<style\b.*?</style>|<script\b.*?</script>",
    )
    .replace_all(html, "");
    let t = re(&BREAK, r"(?i)<br\s*/?>|</(p|div|tr|li|h[1-6]|table)>").replace_all(&t, "\n");
    let t = re(&TAG, r"(?s)<[^>]*>").replace_all(&t, "");
    let t = unescape(&t).replace('\r', "");
    let t = re(&BLANK, r"[ \t\u{a0}]*\n\s*").replace_all(&t, "\n");
    t.trim().to_string()
}

/// The targets of an HTML body's links, leaving out the namespaces of its
/// `<html>` tag.
fn links_of(html: &str) -> String {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let re = LINK.get_or_init(|| {
        Regex::new(r#"(?is)\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("valid regex")
    });
    let targets = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).or(c.get(2)))
        .map(|m| m.as_str());
    targets.collect::<Vec<_>>().join(" ")
}

fn urls_of(texts: &[&str]) -> Vec<String> {
    static URL: OnceLock<Regex> = OnceLock::new();
    let re = URL
        .get_or_init(|| Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s"'<>\\]+"#).expect("valid regex"));
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for m in texts.iter().flat_map(|t| re.find_iter(t)) {
        let url = unescape(m.as_str());
        let url = url.trim_end_matches(['.', ',', ')', ';']).to_string();
        if seen.insert(url.clone()) {
            out.push(url);
            if out.len() == MAX_URLS {
                break;
            }
        }
    }
    out
}

fn named(name: Option<String>, address: Option<String>) -> String {
    match (name, address) {
        (Some(n), Some(a)) if n != a => format!("{n} <{a}>"),
        (Some(n), _) => n,
        (None, Some(a)) => a,
        (None, None) => String::new(),
    }
}

struct Recipients {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
}

fn recipients(r: &Reader<'_>, p: &Props<'_, '_>) -> Recipients {
    let mut out = Recipients {
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
    };
    let subs = p.subnodes();
    let Some(t) = subs
        .get(&NID_RECIPIENTS)
        .and_then(|n| Table::open(r, n, HashMap::new()))
    else {
        return out;
    };
    for i in 0..t.len() {
        let address = t.text(i, PR_SMTP).or_else(|| t.text(i, PR_EMAIL));
        let who = named(t.text(i, PR_DISPLAY_NAME), address);
        match t.int(i, PR_RECIPIENT_TYPE) {
            Some(2) => out.cc.push(who),
            Some(3) => out.bcc.push(who),
            _ => out.to.push(who),
        }
    }
    out
}

struct Attachment {
    name: String,
    mime: Option<String>,
    size: Option<usize>,
    sha256: Option<String>,
    embedded: bool,
}

fn attachments(r: &Reader<'_>, p: &Props<'_, '_>) -> Vec<Attachment> {
    let subs = p.subnodes();
    let Some(t) = subs
        .get(&NID_ATTACHMENTS)
        .and_then(|n| Table::open(r, n, HashMap::new()))
    else {
        return Vec::new();
    };
    let mut ids: Vec<u32> = (0..t.len())
        .filter_map(|i| t.int(i, 0x67F2).map(|v| v as u32))
        .collect();
    ids.sort_unstable();
    let mut out = Vec::new();
    for id in ids {
        let Some(a) = subs.get(&id).and_then(|n| Props::open(r, n)) else {
            r.damaged::<()>();
            continue;
        };
        // Method 5 is a message inside the message.
        let embedded = a.int(PR_ATTACH_METHOD) == Some(5);
        let data = (!embedded).then(|| a.bytes(PR_ATTACH_DATA)).flatten();
        let name = a
            .text(PR_ATTACH_LONG_NAME)
            .or_else(|| a.text(PR_ATTACH_NAME));
        out.push(Attachment {
            name: name.unwrap_or_default(),
            mime: a.text(PR_ATTACH_MIME),
            size: data.as_ref().map(Vec::len),
            sha256: data.map(|d| {
                let hash = Sha256::digest(&d);
                hash.iter().map(|b| format!("{b:02x}")).collect()
            }),
            embedded,
        });
    }
    out
}

struct Walk<'s, 'r> {
    r: &'r Reader<'s>,
    store: &'s Store,
    folders: HashMap<u32, String>,
    mailbox: Option<String>,
}

impl Walk<'_, '_> {
    fn folder(&mut self, nid: u32, depth: u8) -> String {
        if let Some(known) = self.folders.get(&nid) {
            return known.clone();
        }
        let node = self.store.nodes.get(&nid).copied();
        let path = match node {
            Some(n) if nid & 0x1F == NT_FOLDER && depth < 64 => {
                let name = Props::open(self.r, &n)
                    .and_then(|p| p.text(PR_DISPLAY_NAME))
                    .unwrap_or_default();
                if n.parent == nid || n.parent == 0 {
                    String::new()
                } else {
                    format!("{}\\{name}", self.folder(n.parent, depth + 1))
                }
            }
            _ => String::new(),
        };
        self.folders.insert(nid, path.clone());
        path
    }

    fn message(&mut self, nid: u32, node: &Node, out: &mut Vec<Rec>) {
        let Some(p) = Props::open(self.r, node) else {
            return;
        };
        let class = p.text(PR_CLASS).unwrap_or_default();
        let folder = self.folder(node.parent, 0);
        // What the user sees: below the store's technical root.
        let folder = match folder.split_once("\\IPM_SUBTREE\\") {
            Some((_, seen)) => seen.to_string(),
            None => folder.trim_start_matches('\\').to_string(),
        };
        let (created, modified) = (p.time(PR_CREATED), p.time(PR_MODIFIED));
        let (sent, received) = (p.time(PR_CLIENT_SUBMIT), p.time(PR_DELIVERY));
        let ts = sent
            .or(received)
            .or(modified)
            .or(created)
            .unwrap_or_default();
        if class.starts_with("IPM.Contact") {
            let mut c = Rec::new(EID_CONTACT, ts);
            c.s("Folder", folder).s("Name", subject(&p));
            let address = p
                .ids(PT_UNICODE)
                .into_iter()
                .filter(|id| *id >= 0x8000)
                .filter_map(|id| p.text(id))
                .find(|v| v.contains('@') && !v.contains(' '));
            c.opt("Email", address);
            out.push(c);
            return;
        }
        let html = p
            .bytes(PR_HTML)
            .filter(|d| !d.is_empty())
            .map(|d| match p.kind(PR_HTML) {
                Some(PT_UNICODE) => p.text(PR_HTML).unwrap_or_default(),
                _ => ltp::text_of(&d),
            });
        let plain = p.text(PR_BODY);
        let body = plain
            .clone()
            .or_else(|| html.as_deref().map(html_text))
            .unwrap_or_default();
        let links = html.as_deref().map(links_of).unwrap_or_default();
        let urls = urls_of(&[&links, &body]);
        let to = recipients(self.r, &p);
        let att = attachments(self.r, &p);
        let subject = subject(&p);
        let sender = named(
            p.text(PR_SENT_NAME).or_else(|| p.text(PR_SENDER_NAME)),
            p.text(PR_SENT_SMTP)
                .or_else(|| p.text(PR_SENDER_SMTP))
                .or_else(|| p.text(PR_SENT_ADDRESS))
                .or_else(|| p.text(PR_SENDER_ADDRESS)),
        );
        let names: Vec<&str> = att.iter().map(|a| a.name.as_str()).collect();
        let mut m = Rec::new(EID_MESSAGE, ts);
        m.s("Folder", folder.clone())
            .s("Subject", subject.clone())
            .s("From", sender.clone())
            .s("To", to.to.join("; "))
            .s("Cc", to.cc.join("; "))
            .s("Bcc", to.bcc.join("; "))
            .n(
                "RecipientCount",
                (to.to.len() + to.cc.len() + to.bcc.len()) as u64,
            )
            .time("Sent", sent)
            .time("Received", received)
            .time("Created", created)
            .time("Modified", modified)
            .flag(
                "Unsent",
                p.int(PR_FLAGS).is_some_and(|f| f & MSGFLAG_UNSENT != 0),
            )
            .s("MessageClass", class)
            .n("AttachmentCount", att.len() as u64)
            .s("Attachments", names.join("; "))
            .s("Urls", urls.join(" "))
            .s("Body", body)
            .flag(
                "RtfOnly",
                plain.is_none() && html.is_none() && p.bytes(PR_RTF).is_some(),
            )
            .opt("MessageId", p.text(PR_MESSAGE_ID))
            .opt("InReplyTo", p.text(PR_IN_REPLY_TO))
            .opt("Headers", p.text(PR_HEADERS))
            .n("Nid", u64::from(nid));
        out.push(m);
        for a in att {
            let mut r = Rec::new(EID_ATTACHMENT, ts);
            r.s("Folder", folder.clone())
                .s("Subject", subject.clone())
                .s("From", sender.clone())
                .s("FileName", a.name)
                .opt("MimeType", a.mime)
                .opt("Sha256", a.sha256)
                .flag("EmbeddedMessage", a.embedded)
                .n("Nid", u64::from(nid));
            if let Some(size) = a.size {
                r.n("Size", size as u64);
            }
            out.push(r);
        }
    }
}

impl Source for MailSource {
    fn key(&self) -> FileKey {
        self.key
    }
    fn path(&self) -> &Path {
        &self.path
    }
    fn units(&self) -> usize {
        1
    }
    fn byte_len(&self) -> u64 {
        self.len
    }
    fn is_log(&self) -> bool {
        false
    }
    fn open_warnings(&self) -> &[String] {
        &self.warnings
    }
    fn parse_unit(&self, _unit: usize, sink: &mut dyn Sink) -> UnitReport {
        let mut rep = UnitReport::default();
        let r = self.store.reader();
        let mailbox = self
            .store
            .nodes
            .get(&NID_STORE)
            .and_then(|n| Props::open(&r, n))
            .and_then(|p| p.text(PR_DISPLAY_NAME));
        let mut walk = Walk {
            r: &r,
            store: &self.store,
            folders: HashMap::new(),
            mailbox,
        };
        let mut n = 0u64;
        for (&nid, node) in &self.store.nodes {
            if nid & 0x1F != NT_MESSAGE {
                continue;
            }
            let mut recs = Vec::new();
            walk.message(nid, node, &mut recs);
            for rec in recs {
                n += 1;
                if !sink.want_event_id(rec.eid) || !sink.want_time(rec.ts) {
                    continue;
                }
                let mut fields = rec.fields;
                if let Some(m) = &walk.mailbox {
                    fields.insert(0, field("Mailbox", Val::Str(Cow::Owned(m.clone()))));
                }
                if !self.user.is_empty() {
                    fields.insert(0, field("User", Val::Str(Cow::Owned(self.user.clone()))));
                }
                sink.event(&EventView {
                    id: EventRef {
                        file: self.key,
                        record: n,
                    },
                    ts: rec.ts,
                    event_id: rec.eid,
                    provider: Cow::Borrowed(PROVIDER),
                    channel: Cow::Borrowed(CHANNEL),
                    computer: Cow::Borrowed(&self.host),
                    event_record_id: n,
                    fields,
                    ..EventView::default()
                });
            }
        }
        rep.records = n;
        let (bad, cut) = r.damage();
        if bad > 0 {
            rep.bad_records = bad;
            rep.note(|| format!("{bad} unreadable mailbox items"));
        }
        if cut {
            rep.bad_records += 1;
            rep.note(|| "items repeat beyond the size of the mailbox: output cut".into());
        }
        rep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mail/WS-07/C/Users/jdoe/AppData/Local/Microsoft/Outlook")
            .join(name)
    }

    #[test]
    fn html_becomes_text_and_links() {
        let html = "<html xmlns:o=\"http://schemas.example.test/o\"><head><style>a{}</style></head>\
                    <body><p>A &amp; B&#33;</p><!-- x --><a href='http://a.test/x?a=1&amp;b=2'>y</a>\
                    </body></html>";
        assert_eq!(html_text(html), "A & B!\ny");
        let links = links_of(html);
        assert_eq!(
            urls_of(&[&links, "see https://b.test/c."]),
            ["http://a.test/x?a=1&b=2", "https://b.test/c"]
        );
    }

    #[test]
    fn the_owner_comes_from_the_profile() {
        let user = |p: &str| user_of(Path::new(p));
        assert_eq!(
            user("/x/Users/ann/AppData/Local/Microsoft/Outlook/a.ost"),
            "ann"
        );
        assert_eq!(user("/Users/analyst/case/a.pst"), "");
    }

    /// Any byte of a mailbox can be wrong: parsing must end, without a panic.
    #[test]
    fn damage_never_panics() {
        for name in ["archive.pst", "jdoe@contoso.test.ost"] {
            let good = std::fs::read(fixture(name)).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("m.pst");
            let mut seed = 0x2545_F491_4F6C_DD1Du64;
            let mut next = move || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as usize
            };
            for _ in 0..300 {
                let mut bad = good.clone();
                for _ in 0..40 {
                    let at = 564 + next() % (bad.len() - 564);
                    bad[at] = next() as u8;
                }
                std::fs::write(&path, &bad).unwrap();
                if let Ok(s) = MailSource::open(&path, &ParseOptions::default()) {
                    s.parse_unit(0, &mut |_: &EventView<'_>| {});
                }
            }
        }
    }
}
