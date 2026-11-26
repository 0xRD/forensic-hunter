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
    let (_, r) = load_str(
        "title: A\nid: x\nlevel: high\ndetection:\n  a:\n    A: 1\n  condition: a | count() > 3\n",
        &LoadOptions::default(),
    );
    assert_eq!(r.skipped_total(), 1);
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
