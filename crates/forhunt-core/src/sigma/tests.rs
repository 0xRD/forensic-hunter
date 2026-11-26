use std::borrow::Cow;

use super::*;
use crate::event::{Field, Val};

fn ev(channel: &str, eid: u32, fields: &[(&str, &str)]) -> EventView<'static> {
    EventView {
        channel: Cow::Owned(channel.into()),
        event_id: eid,
        provider: Cow::Borrowed("Microsoft-Windows-Security-Auditing"),
        computer: Cow::Borrowed("WS-07.contoso.local"),
        fields: fields
            .iter()
            .map(|(k, v)| Field {
                name: Cow::Owned(k.to_string()),
                value: Val::Str(Cow::Owned(v.to_string())),
            })
            .collect(),
        ..Default::default()
    }
}

fn rule(detection: &str) -> RuleSet {
    let text = format!(
        "title: T\nid: 00000000-0000-0000-0000-000000000001\nlevel: high\nstatus: test\nauthor: Ann\nlogsource:\n  product: windows\ndetection:\n{detection}"
    );
    let (set, rep) = load_str(&text, &LoadOptions::default());
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(set.len(), 1, "{rep:?}");
    set
}

fn hit(set: &RuleSet, e: &EventView<'_>) -> bool {
    let mut out = Vec::new();
    set.matcher().matches(e, &mut out);
    !out.is_empty()
}

const PROC: &str = "Microsoft-Windows-Sysmon/Operational";

#[test]
fn equality_is_case_insensitive_and_lists_or() {
    let s = rule(
        "  sel:\n    Channel: Microsoft-Windows-Sysmon/Operational\n    EventID: 1\n    Image:\n      - 'C:\\Windows\\System32\\whoami.exe'\n      - 'C:\\x.exe'\n  condition: sel\n",
    );
    assert!(hit(
        &s,
        &ev(PROC, 1, &[("Image", "c:\\windows\\system32\\WHOAMI.exe")])
    ));
    assert!(!hit(
        &s,
        &ev(PROC, 1, &[("Image", "c:\\windows\\system32\\whoami.exe2")])
    ));
    // Wrong channel / id: not even a candidate.
    assert!(!hit(&s, &ev("Security", 1, &[("Image", "C:\\x.exe")])));
    assert!(!hit(&s, &ev(PROC, 3, &[("Image", "C:\\x.exe")])));
    assert!(s.wants_event_id(1) && !s.wants_event_id(4688));
}

#[test]
fn contains_starts_ends_all() {
    let s = rule(
        "  sel:\n    CommandLine|contains|all:\n      - ' -nop '\n      - ' -w hidden '\n    Image|endswith: '\\powershell.exe'\n    ParentImage|startswith: 'C:\\Windows\\'\n  condition: sel\n",
    );
    let good = [
        ("CommandLine", "powershell.exe -NoP -nop -W hidden -enc AAA"),
        (
            "Image",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE",
        ),
        ("ParentImage", "c:\\windows\\explorer.exe"),
    ];
    assert!(hit(&s, &ev("X", 1, &good)));
    let mut bad = good;
    bad[0].1 = "powershell.exe -nop -enc AAA";
    assert!(!hit(&s, &ev("X", 1, &bad)));
}

#[test]
fn wildcards() {
    let s = rule(
        "  sel:\n    TargetFilename: 'C:\\Users\\\\*\\AppData\\\\*.lnk'\n    Name: 'a?c'\n  condition: sel\n",
    );
    assert!(hit(
        &s,
        &ev(
            "X",
            11,
            &[
                ("TargetFilename", "C:\\Users\\bob\\AppData\\Roaming\\x.LNK"),
                ("Name", "abc")
            ]
        )
    ));
    assert!(!hit(
        &s,
        &ev(
            "X",
            11,
            &[
                ("TargetFilename", "C:\\Users\\bob\\AppData\\x.lnk.txt"),
                ("Name", "abc")
            ]
        )
    ));
    assert!(!hit(
        &s,
        &ev(
            "X",
            11,
            &[
                ("TargetFilename", "C:\\Users\\bob\\AppData\\x.lnk"),
                ("Name", "abbc")
            ]
        )
    ));
    // Escaped wildcard is literal.
    let s = rule("  sel:\n    Name: 'a\\*b'\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 1, &[("Name", "a*b")])));
    assert!(!hit(&s, &ev("X", 1, &[("Name", "axb")])));
}

#[test]
fn not_one_of_all_of_them() {
    let s = rule(
        "  selection_a:\n    A: x\n  selection_b:\n    B: y\n  filter_1:\n    C: z\n  condition: 1 of selection_* and not filter_1\n",
    );
    assert!(hit(&s, &ev("X", 1, &[("A", "x")])));
    assert!(hit(&s, &ev("X", 1, &[("B", "y")])));
    assert!(!hit(&s, &ev("X", 1, &[("B", "y"), ("C", "Z")])));
    let s = rule("  a:\n    A: x\n  b:\n    B: y\n  condition: all of them\n");
    assert!(!hit(&s, &ev("X", 1, &[("A", "x")])));
    assert!(hit(&s, &ev("X", 1, &[("A", "x"), ("B", "y")])));
}

#[test]
fn null_and_exists() {
    let s = rule("  sel:\n    A: x\n    B: null\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 1, &[("A", "x")])));
    assert!(hit(&s, &ev("X", 1, &[("A", "x"), ("B", "")])));
    assert!(!hit(&s, &ev("X", 1, &[("A", "x"), ("B", "v")])));
    let s = rule("  sel:\n    B|exists: true\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 1, &[("B", "")])));
    assert!(!hit(&s, &ev("X", 1, &[("A", "")])));
}

#[test]
fn regex_is_case_sensitive_unless_i() {
    let s = rule("  sel:\n    CommandLine|re: '-enc\\s+[A-Za-z0-9+/=]{8,}'\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 1, &[("CommandLine", "x -enc SQBFAFgA")])));
    assert!(!hit(&s, &ev("X", 1, &[("CommandLine", "x -ENC SQBFAFgA")])));
    let s = rule("  sel:\n    CommandLine|re|i: '-enc\\s'\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 1, &[("CommandLine", "x -ENC A")])));
}

#[test]
fn windash_base64offset_wide_cidr() {
    let s = rule("  sel:\n    CommandLine|contains|windash: ' -decode '\n  condition: sel\n");
    assert!(hit(
        &s,
        &ev("X", 1, &[("CommandLine", "certutil /decode a b")])
    ));
    assert!(hit(
        &s,
        &ev("X", 1, &[("CommandLine", "certutil \u{2013}decode a b")])
    ));
    assert!(!hit(
        &s,
        &ev("X", 1, &[("CommandLine", "certutil decode a b")])
    ));

    // "IEX" encoded as UTF-16LE inside a base64 PowerShell command.
    let s = rule("  sel:\n    CommandLine|wide|base64offset|contains: 'IEX ('\n  condition: sel\n");
    let enc = compile::base64(
        &"x;IEX (New"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    assert!(hit(
        &s,
        &ev(
            "X",
            1,
            &[("CommandLine", &format!("powershell -enc {enc}"))]
        )
    ));
    assert!(!hit(
        &s,
        &ev("X", 1, &[("CommandLine", "powershell -enc AAAA")])
    ));

    let s = rule(
        "  sel:\n    IpAddress|cidr:\n      - '10.0.0.0/8'\n      - '192.168.0.0/16'\n  condition: sel\n",
    );
    assert!(hit(&s, &ev("X", 1, &[("IpAddress", "::ffff:10.2.3.4")])));
    assert!(!hit(&s, &ev("X", 1, &[("IpAddress", "203.0.113.5")])));
}

#[test]
fn fieldref_numbers_keywords() {
    let s = rule("  sel:\n    TargetUserName|fieldref: SubjectUserName\n  condition: sel\n");
    assert!(hit(
        &s,
        &ev(
            "X",
            1,
            &[("TargetUserName", "Bob"), ("SubjectUserName", "bob")]
        )
    ));
    assert!(!hit(
        &s,
        &ev(
            "X",
            1,
            &[("TargetUserName", "Bob"), ("SubjectUserName", "al")]
        )
    ));
    let s = rule("  sel:\n    Size|gte: 1000\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 1, &[("Size", "0x400")])));
    assert!(!hit(&s, &ev("X", 1, &[("Size", "999")])));
    let s = rule("  keywords:\n    - 'mimikatz'\n    - 'sekurlsa::*'\n  condition: keywords\n");
    assert!(hit(&s, &ev("X", 1, &[("Msg", "running Mimikatz now")])));
    assert!(hit(&s, &ev("X", 1, &[("Msg", "sekurlsa::logonpasswords")])));
    assert!(!hit(&s, &ev("X", 1, &[("Msg", "nothing")])));
}

#[test]
fn values_stay_as_written() {
    // YAML would read 0x1410 as 5136: the text must stay.
    let s = rule("  sel:\n    GrantedAccess: 0x1410\n  condition: sel\n");
    assert!(hit(&s, &ev("X", 10, &[("GrantedAccess", "0x1410")])));
}

#[test]
fn list_items_and_system_values() {
    // forhunt names unnamed <Data> items Data[1], Data[2]...
    let s = rule("  sel:\n    Data|contains: 'HostApplication=powershell'\n  condition: sel\n");
    assert!(hit(
        &s,
        &ev(
            "Windows PowerShell",
            400,
            &[
                ("Data[1]", "Available"),
                ("Data[2]", "HostApplication=powershell -nop")
            ]
        )
    ));
    let s = rule(
        "  sel:\n    Provider_Name: Microsoft-Windows-Security-Auditing\n    Computer|startswith: ws-\n  condition: sel\n",
    );
    assert!(hit(&s, &ev("Security", 4624, &[])));
}

#[test]
fn index_handles_or_and_not() {
    let s = rule(
        "  a:\n    Channel: Security\n    EventID: 4624\n  b:\n    Channel: System\n    EventID: [7045, 7036]\n  condition: a or b\n",
    );
    assert_eq!(s.candidates("security", 4624), vec![0]);
    assert_eq!(s.candidates("System", 7045), vec![0]);
    // The index over-approximates (Security x 7045 is a candidate); the
    // condition still decides.
    assert!(!hit(&s, &ev("Security", 7045, &[])));
    let s = rule("  a:\n    Channel: Security\n  condition: not a\n");
    assert_eq!(s.candidates("System", 1), vec![0]);
    assert!(!s.wants_event_id(0) || s.wants_event_id(123));
}

#[test]
fn skips_and_errors_are_reported() {
    let (s, r) = load_str(
        "title: A\nid: x\nlevel: high\nstatus: deprecated\ndetection:\n  a:\n    A: 1\n  condition: a\n",
        &LoadOptions::default(),
    );
    assert!(s.is_empty());
    assert_eq!(r.skipped.get("status deprecated"), Some(&1));
    let (_, r) = load_str(
        "title: A\nid: x\nlevel: low\ndetection:\n  a:\n    A: 1\n  condition: a\n",
        &LoadOptions {
            min_level: 3,
            ..Default::default()
        },
    );
    assert_eq!(r.skipped_total(), 1);
    let (_, r) = load_str(
        "title: A\nid: x\nlevel: high\ndetection:\n  a:\n    A|bogus: 1\n  condition: a\n",
        &LoadOptions::default(),
    );
    assert_eq!(r.errors.len(), 1);
    // `| count()` is a correlation over a hidden base rule.
    let (s, r) = load_str(
        "title: A\nid: x\nlevel: high\ndetection:\n  a:\n    A: 1\n  condition: a | count() > 3\n",
        &LoadOptions::default(),
    );
    assert!(r.errors.is_empty(), "{r:?}");
    assert_eq!(s.len(), 2);
    assert_eq!(r.loaded, 1);
    assert!(s.rules().iter().any(|x| x.hidden && x.id == "x:base"));
    assert!(s.rules().iter().any(|x| x.corr.is_some() && x.id == "x"));
}

fn at(min: i64, mut e: EventView<'static>) -> EventView<'static> {
    e.ts = crate::Ts(min * 60 * 10_000_000);
    e
}

/// Matches, observes and correlates events: (rule title, member indexes).
fn correlate(set: &RuleSet, evs: &[EventView<'static>]) -> Vec<(String, Vec<usize>)> {
    let mut m = set.matcher();
    let mut obs = Vec::new();
    for (i, e) in evs.iter().enumerate() {
        let mut hits = Vec::new();
        m.matches(e, &mut hits);
        let mut o = Vec::new();
        set.observe(e, &hits, &mut o);
        obs.extend(o.into_iter().map(|x| (x, i)));
    }
    set.correlate(obs)
        .into_iter()
        .map(|b| (set.rules()[b.rule as usize].title.clone(), b.members))
        .collect()
}

#[test]
fn correlations_end_to_end() {
    // Sigma 2: value_count over a named rule in the same file, group-by.
    let text = "title: Failed logon\nname: failed\nid: f\nlevel: low\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel\n---\ntitle: Spray\nid: spray\nlevel: high\ncorrelation:\n  type: value_count\n  rules:\n    - failed\n  group-by:\n    - IpAddress\n  timespan: 10m\n  condition:\n    gte: 3\n    field: TargetUserName\n";
    let (s, r) = load_str(text, &LoadOptions::default());
    assert!(r.errors.is_empty(), "{r:?}");
    // The base rule does not report on its own (`generate` is false).
    assert!(s.rules().iter().find(|x| x.id == "f").unwrap().hidden);
    let f = |min, user: &str, ip: &str| {
        at(
            min,
            ev(
                "Security",
                4625,
                &[("TargetUserName", user), ("IpAddress", ip)],
            ),
        )
    };
    let evs = vec![
        f(0, "alice", "10.0.0.9"),
        f(1, "bob", "10.0.0.9"),
        f(2, "carol", "10.0.0.9"),
        f(3, "alice", "10.0.0.7"),
        f(40, "dave", "10.0.0.9"),
    ];
    assert_eq!(
        correlate(&s, &evs),
        vec![("Spray".to_string(), vec![0, 1, 2])]
    );
    // Below the minimum level, a base rule is still kept for its correlation.
    let (s, _) = load_str(
        text,
        &LoadOptions {
            min_level: 4,
            ..Default::default()
        },
    );
    assert_eq!(s.len(), 2);
    // Deprecated aggregation: count() by over a timeframe.
    let text = "title: Burst\nid: b\nlevel: medium\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4625\n  timeframe: 5m\n  condition: sel | count() by IpAddress >= 3\n";
    let (s, r) = load_str(text, &LoadOptions::default());
    assert!(r.errors.is_empty(), "{r:?}");
    assert_eq!(
        correlate(&s, &evs),
        vec![("Burst".to_string(), vec![0, 1, 2])]
    );
    // Temporal ordered: a logon then a service install within the span.
    let text = "title: L\nname: logon\nid: l\nlevel: low\ndetection:\n  sel:\n    Channel: Security\n    EventID: 4624\n  condition: sel\n---\ntitle: S\nname: svc\nid: s\nlevel: low\ndetection:\n  sel:\n    Channel: System\n    EventID: 7045\n  condition: sel\n---\ntitle: Logon then service\nid: ls\nlevel: high\ncorrelation:\n  type: temporal_ordered\n  rules: [logon, svc]\n  group-by: [Computer]\n  timespan: 5m\n";
    let (s, r) = load_str(text, &LoadOptions::default());
    assert!(r.errors.is_empty(), "{r:?}");
    let evs = vec![
        at(0, ev("System", 7045, &[])),
        at(1, ev("Security", 4624, &[])),
        at(3, ev("System", 7045, &[])),
    ];
    assert_eq!(
        correlate(&s, &evs),
        vec![("Logon then service".to_string(), vec![1, 2])]
    );
    // A correlation naming a rule that is not there is an error, not a silent skip.
    let (_, r) = load_str(
        "title: X\nid: x\nlevel: high\ncorrelation:\n  type: event_count\n  rules: [nope]\n  timespan: 5m\n  condition:\n    gte: 2\n",
        &LoadOptions::default(),
    );
    assert_eq!(r.errors.len(), 1);
}

#[test]
fn details_template() {
    let text = "title: T\nid: d\nlevel: high\ndetails: 'Cmd: %CommandLine% ¦ User: %User% ¦ Gone: %Nope%'\ndetection:\n  a:\n    CommandLine|contains: x\n  condition: a\n";
    let (s, _) = load_str(text, &LoadOptions::default());
    let e = ev("X", 1, &[("CommandLine", "x y"), ("User", "bob")]);
    assert_eq!(
        s.details(0, &e),
        vec![
            ("Cmd".into(), "x y".into()),
            ("User".into(), "bob".into()),
            ("Gone".into(), "n/a".into())
        ]
    );
    assert_eq!(s.rules()[0].author, "");
}

#[test]
fn folder_of_checkouts_and_own_rules() {
    let d = tempfile::tempdir().unwrap();
    let hr = d.path().join("hayabusa-rules");
    std::fs::create_dir_all(hr.join("config")).unwrap();
    std::fs::create_dir_all(hr.join("sigma")).unwrap();
    std::fs::create_dir_all(hr.join("scripts")).unwrap();
    std::fs::create_dir_all(d.path().join("custom")).unwrap();
    let r = |id: &str| {
        format!("title: {id}\nid: {id}\nlevel: high\ndetection:\n  a:\n    A: x\n  condition: a\n")
    };
    std::fs::write(hr.join("config/exclude_rules.txt"), "ex # excluded\n").unwrap();
    std::fs::write(hr.join("sigma/a.yml"), r("a")).unwrap();
    std::fs::write(hr.join("sigma/ex.yml"), r("ex")).unwrap();
    // Test fixtures of the rules repository are not rules.
    std::fs::write(hr.join("scripts/fixture.yml"), r("fixture")).unwrap();
    std::fs::write(d.path().join("custom/mine.yml"), r("mine")).unwrap();
    let (set, rep) = load(&[d.path().to_path_buf()], &LoadOptions::default());
    let mut ids: Vec<&str> = set.rules().iter().map(|r| r.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["a", "mine"], "{rep:?}");
    assert_eq!(rep.skipped.get("excluded (exclude_rules.txt)"), Some(&1));
}

#[test]
fn expand_values_from_own_config() {
    let d = tempfile::tempdir().unwrap();
    let own = d.path().join("custom");
    std::fs::create_dir_all(own.join("config/expand")).unwrap();
    std::fs::write(
        own.join("config/expand/admins.txt"),
        "alice\nbob # comment\n",
    )
    .unwrap();
    std::fs::write(
        own.join("r.yml"),
        "title: E\nid: e\nlevel: high\ndetection:\n  a:\n    User|expand: '%admins%'\n  condition: a\n",
    )
    .unwrap();
    // From the folder above (as `rules/`) and from the folder itself.
    for root in [d.path().to_path_buf(), own.clone()] {
        let (set, rep) = load(&[root], &LoadOptions::default());
        assert_eq!(set.len(), 1, "{rep:?}");
        assert!(hit(&set, &ev("X", 1, &[("User", "Bob")])));
        assert!(!hit(&set, &ev("X", 1, &[("User", "eve")])));
    }
}

#[test]
fn logsource_variants() {
    let text = "title: Whoami\nid: w\nlevel: high\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\whoami.exe'\n    IntegrityLevel: High\n  condition: sel\n";
    let (s, r) = load_str(text, &LoadOptions::default());
    assert_eq!(s.len(), 1, "{r:?}");
    let sysmon = "Microsoft-Windows-Sysmon/Operational";
    assert!(hit(
        &s,
        &ev(
            sysmon,
            1,
            &[
                ("Image", "C:\\Windows\\System32\\whoami.exe"),
                ("IntegrityLevel", "High")
            ]
        )
    ));
    // Security 4688: renamed field, mapped value.
    assert!(hit(
        &s,
        &ev(
            "Security",
            4688,
            &[
                ("NewProcessName", "C:\\Windows\\System32\\whoami.exe"),
                ("MandatoryLabel", "S-1-16-12288")
            ]
        )
    ));
    // Other logs: not even candidates.
    assert!(!hit(
        &s,
        &ev(
            sysmon,
            5,
            &[
                ("Image", "C:\\Windows\\System32\\whoami.exe"),
                ("IntegrityLevel", "High")
            ]
        )
    ));
    assert!(s.candidates("Application", 1).is_empty());
    // As written: the logsource is ignored.
    let (s, _) = load_str(
        text,
        &LoadOptions {
            profile: Profile::AsWritten,
            ..Default::default()
        },
    );
    assert!(hit(
        &s,
        &ev(
            "Application",
            1,
            &[("Image", "x\\whoami.exe"), ("IntegrityLevel", "High")]
        )
    ));
    // Other products are skipped, with the reason.
    let (s, r) = load_str(
        &text.replace("product: windows", "product: linux"),
        &LoadOptions::default(),
    );
    assert!(s.is_empty());
    assert!(r.skipped.keys().any(|k| k.contains("linux")), "{r:?}");
    // A rule naming its Channel runs as written under Auto.
    let t2 = "title: C\nid: c\nlevel: high\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    Channel: Security\n    EventID: 1102\n  condition: sel\n";
    let (s, _) = load_str(t2, &LoadOptions::default());
    assert!(hit(&s, &ev("Security", 1102, &[])));
    // `service: security` + EventID (no Channel): mapped to the Security log.
    let t3 = "title: S\nid: s\nlevel: high\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4624\n  condition: sel\n";
    let (s, _) = load_str(t3, &LoadOptions::default());
    assert!(hit(&s, &ev("Security", 4624, &[])));
    assert!(!hit(&s, &ev("System", 4624, &[])));
}

#[test]
fn all_with_windash_and_lenient_yaml() {
    let s = rule(
        "  sel:\n    CommandLine|contains|all|windash:\n      - ' -s '\n      - ' -q '\n  condition: sel\n",
    );
    assert!(hit(&s, &ev("X", 1, &[("CommandLine", "x /s /q y")])));
    assert!(hit(&s, &ev("X", 1, &[("CommandLine", "x -s /q y")])));
    assert!(!hit(&s, &ev("X", 1, &[("CommandLine", "x -s y")])));
    // Unquoted `*value`, and a bare `sel_*` in the condition.
    let text = "title: L\nid: l\nlevel: high\ndetection:\n  sel_a:\n    Image:\n      - *\\evil.exe\n  condition: sel_*\n";
    let (s, r) = load_str(text, &LoadOptions::default());
    assert_eq!(s.len(), 1, "{r:?}");
    assert!(hit(&s, &ev("X", 1, &[("Image", "C:\\evil.exe")])));
}

#[test]
fn non_ascii_names_and_values() {
    // An event field name with a multibyte char where the rule's name ends:
    // no match, no panic.
    let s = rule("  sel:\n    Datas: x\n  condition: sel\n");
    assert!(!hit(&s, &ev(PROC, 1, &[("Données", "x")])));
    // A word-final Σ in the needle still matches inside a word.
    let s = rule("  sel:\n    CommandLine|contains: 'ΟΔΟΣ'\n  condition: sel\n");
    assert!(hit(&s, &ev(PROC, 1, &[("CommandLine", "xΟΔΟΣΑ")])));
}

/// hayabusa-rules copies of SigmaHQ rules (`related: derived`).
const ORIG: &str = "title: Orig\nid: aaaa\nlevel: high\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel\n";
const COPY: &str = "title: Copy\nid: bbbb\nlevel: high\nrelated:\n  - id: aaaa\n    type: derived\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel\n";

#[test]
fn converted_copies_supersede_their_rule() {
    let ids = |s: &RuleSet| s.rules().iter().map(|r| r.id.clone()).collect::<Vec<_>>();
    let both = format!("{ORIG}---\n{COPY}");
    let (s, r) = load_str(&both, &LoadOptions::default());
    assert_eq!(ids(&s), ["bbbb"]);
    assert_eq!(r.skipped.values().sum::<usize>(), 1);
    // Selecting the original by id: it runs (its copy is not selected).
    let opts = LoadOptions {
        ids: vec!["aaaa".into()],
        ..Default::default()
    };
    assert_eq!(ids(&load_str(&both, &opts).0), ["aaaa"]);
    // A copy below the minimum level does not take the original away.
    let low = both.replacen("level: high\nrelated", "level: low\nrelated", 1);
    let opts = LoadOptions {
        min_level: 4,
        ..Default::default()
    };
    assert_eq!(ids(&load_str(&low, &opts).0), ["aaaa"]);
    // A superseded `| count()` rule takes its hidden base rule with it.
    let count = ORIG.replace("condition: sel", "condition: sel | count() > 3");
    let (s, _) = load_str(&format!("{count}---\n{COPY}"), &LoadOptions::default());
    assert_eq!(ids(&s), ["bbbb"]);
}

#[test]
fn count_rules_without_id_keep_their_own_base() {
    let a = "title: A\nlevel: high\ndetection:\n  sel:\n    EventID: 1\n  condition: sel | count() > 3\n";
    let b = a
        .replace("title: A", "title: B")
        .replace("EventID: 1", "EventID: 2");
    let (s, r) = load_str(&format!("{a}---\n{b}"), &LoadOptions::default());
    assert!(r.errors.is_empty(), "{r:?}");
    assert_eq!(r.loaded, 2);
    let rules = s.rules();
    assert!(rules.iter().filter(|x| x.corr.is_none()).all(|x| x.hidden));
    // Each correlation counts its own base rule.
    for c in rules
        .iter()
        .filter_map(|x| x.corr.as_deref().map(|c| (x, c)))
    {
        let base = &rules[c.1.rules[0] as usize];
        assert!(
            base.id.contains(&format!("#{}:base", c.0.title)),
            "{}",
            base.id
        );
    }
}

#[test]
fn group_values_are_reported_as_written() {
    let text = "title: Failed\nname: failed\nid: f\nlevel: low\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel\n---\ntitle: Burst\nid: b\nlevel: high\ncorrelation:\n  type: event_count\n  rules: [failed]\n  group-by: [TargetUserName]\n  timespan: 10m\n  condition:\n    gte: 2\n";
    let (s, _) = load_str(text, &LoadOptions::default());
    let evs = [
        at(
            0,
            ev("Security", 4625, &[("TargetUserName", "Administrator")]),
        ),
        at(
            1,
            ev("Security", 4625, &[("TargetUserName", "ADMINISTRATOR")]),
        ),
    ];
    let mut m = s.matcher();
    let mut obs = Vec::new();
    for (i, e) in evs.iter().enumerate() {
        let mut hits = Vec::new();
        m.matches(e, &mut hits);
        let mut o = Vec::new();
        s.observe(e, &hits, &mut o);
        obs.extend(o.into_iter().map(|x| (x, i)));
    }
    // One group (case-insensitive), named as the first event wrote it.
    let b = s.correlate(obs);
    assert_eq!(b.len(), 1);
    assert_eq!(&*b[0].group, "Administrator");
    assert_eq!(b[0].members, [0, 1]);
}

/// The literal gate never changes which rules match.
#[test]
fn gated_and_ungated_agree() {
    let text = [
        "detection:\n  sel:\n    CommandLine|contains|all: [' -enc', 'hidden']\n  condition: sel",
        "detection:\n  sel:\n    Image|endswith: ['\\\\cmd.exe', '\\\\powershell.exe']\n  filter:\n    User: SYSTEM\n  condition: sel and not filter",
        "detection:\n  a:\n    CommandLine|contains: whoami\n  b:\n    ParentImage|endswith: '\\\\w3wp.exe'\n  condition: a or b",
        "detection:\n  sel:\n    CommandLine|re: '(?i)invoke-\\w+'\n  condition: sel",
        "detection:\n  kw:\n    - mimikatz\n  condition: kw",
        "detection:\n  sel:\n    EventID: 1\n    Image|contains: '\\\\temp\\\\'\n  condition: sel",
        "detection:\n  sel:\n    CommandLine|windash|contains: ' -nop'\n  condition: sel",
    ]
    .iter()
    .enumerate()
    .map(|(i, d)| {
        format!("title: R{i}\nid: r{i}\nlevel: high\nlogsource:\n  product: windows\n  category: process_creation\n{d}\n")
    })
    .collect::<Vec<_>>()
    .join("---\n");
    let (s, r) = load_str(&text, &LoadOptions::default());
    assert!(r.errors.is_empty(), "{r:?}");
    assert_eq!(s.len(), 7);
    let images = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe",
        "C:\\x\\POWERSHELL.EXE",
    ];
    let lines = [
        "powershell -ENC aaa -w hidden",
        "whoami /all",
        "x Invoke-Mimikatz",
        "a /nop b",
        "plain",
        "Données é",
    ];
    let parents = ["C:\\w\\w3wp.exe", "C:\\Windows\\explorer.exe"];
    let users = ["SYSTEM", "bob"];
    let mut m = s.matcher();
    let mut n = 0;
    for img in images {
        for cl in lines {
            for p in parents {
                for u in users {
                    let e = ev(
                        PROC,
                        1,
                        &[
                            ("Image", img),
                            ("CommandLine", cl),
                            ("ParentImage", p),
                            ("User", u),
                        ],
                    );
                    let (mut a, mut b) = (Vec::new(), Vec::new());
                    m.matches(&e, &mut a);
                    m.matches_ungated(&e, &mut b);
                    assert_eq!(a, b, "{img} | {cl} | {p} | {u}");
                    n += a.len();
                }
            }
        }
    }
    assert!(n > 20, "the events match some rules ({n})");
}
