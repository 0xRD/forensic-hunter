//! Expands command-line paths (files, directories, globs) into a sorted,
//! de-duplicated list of artifact files.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use rayon::prelude::*;

use crate::artifact::{Artifact, ParseOptions, Source};
use crate::id::FileKey;

#[derive(Debug, Default)]
pub struct Expanded {
    pub files: Vec<PathBuf>,
    /// Arguments that matched nothing.
    pub missing: Vec<String>,
    /// Folders or links that could not be walked (permissions, loops):
    /// files under them may be missing.
    pub errors: Vec<String>,
}

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '[', '{'])
}

/// Explicit files are always taken (the artifact is sniffed at open time);
/// directories are walked recursively and keep files an artifact claims by
/// name. Globs are matched against the walk of their literal prefix.
pub fn expand(args: &[String], artifacts: &[Box<dyn Artifact>]) -> anyhow::Result<Expanded> {
    let mut out = BTreeSet::new();
    let mut missing = Vec::new();
    let mut errors = Vec::new();
    let claimed = |p: &Path| artifacts.iter().any(|a| a.matches_name(p));
    for arg in args {
        let p = Path::new(arg);
        if p.is_file() {
            out.insert(p.to_path_buf());
        } else if p.is_dir() {
            let before = out.len();
            walk(
                p,
                &mut |f| {
                    if claimed(f) {
                        out.insert(f.to_path_buf());
                    }
                },
                &mut errors,
            );
            if out.len() == before {
                missing.push(arg.clone());
            }
        } else if has_glob(arg) {
            let glob = globset::GlobBuilder::new(arg)
                .case_insensitive(cfg!(windows) || cfg!(target_os = "macos"))
                .literal_separator(false)
                .build()?
                .compile_matcher();
            let base = literal_prefix(arg);
            let before = out.len();
            walk(
                &base,
                &mut |f| {
                    if glob.is_match(f) || f.strip_prefix("./").is_ok_and(|s| glob.is_match(s)) {
                        out.insert(f.to_path_buf());
                    }
                },
                &mut errors,
            );
            if out.len() == before {
                missing.push(arg.clone());
            }
        } else {
            missing.push(arg.clone());
        }
    }
    Ok(Expanded {
        files: out.into_iter().collect(),
        missing,
        errors,
    })
}

fn literal_prefix(pat: &str) -> PathBuf {
    let mut base = PathBuf::new();
    for comp in Path::new(pat).components() {
        let s = comp.as_os_str().to_string_lossy();
        if has_glob(&s) {
            break;
        }
        base.push(comp);
    }
    if base.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        base
    }
}

/// Walks `dir`, following links (collections are sometimes trees of links;
/// loops are detected), and records what could not be read instead of
/// silently skipping it.
fn walk(dir: &Path, f: &mut dyn FnMut(&Path), errors: &mut Vec<String>) {
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(true)
        .sort_by_file_name()
    {
        match entry {
            Ok(entry) if entry.file_type().is_file() => f(entry.path()),
            Ok(_) => {}
            Err(e) => {
                let at = e
                    .path()
                    .map_or_else(|| dir.display().to_string(), |p| p.display().to_string());
                let why = e
                    .io_error()
                    .map_or_else(|| e.to_string(), |io| io.to_string());
                errors.push(format!("{at}: not searched ({why})"));
            }
        }
    }
}

/// Opens one artifact file: sniffs its first bytes, falls back to its name.
pub fn open_one(
    arts: &[Box<dyn Artifact>],
    p: &Path,
    opts: &ParseOptions,
) -> anyhow::Result<Arc<dyn Source>> {
    let mut head = [0u8; 8192];
    let n = {
        use std::io::Read;
        let mut f =
            std::fs::File::open(p).with_context(|| format!("{}: cannot open", p.display()))?;
        let mut n = 0;
        while n < head.len() {
            let r = f.read(&mut head[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        n
    };
    let art = arts
        .iter()
        .find(|a| a.sniff(&head[..n]))
        .or_else(|| arts.iter().find(|a| a.matches_name(p)))
        .ok_or_else(|| anyhow::anyhow!("{}: unrecognised artifact type", p.display()))?;
    art.open(p, opts)
}

/// Inputs ready for the engine.
#[derive(Default)]
pub struct Opened {
    pub sources: Vec<Arc<dyn Source>>,
    /// Files found by [`expand`] (before opening).
    pub found: usize,
    /// Files that could not be opened.
    pub failed: usize,
    /// Total size of the opened sources.
    pub bytes: u64,
    /// Human-readable problems, in order: unmatched arguments, open
    /// warnings, skipped duplicates, unreadable files.
    pub warnings: Vec<String>,
}

/// Expands `paths` and opens every input in parallel on `pool`. Unreadable
/// or non-artifact files are reported in `warnings` and skipped;
/// byte-identical inputs (same file key) are opened once. Never fails just
/// because nothing could be opened: check `sources`.
pub fn open_all(
    paths: &[String],
    opts: &ParseOptions,
    pool: &rayon::ThreadPool,
) -> anyhow::Result<Opened> {
    let arts = crate::artifact::registry();
    let exp = expand(paths, &arts)?;
    let mut o = Opened {
        found: exp.files.len(),
        ..Opened::default()
    };
    for e in &exp.errors {
        o.warnings.push(e.clone());
    }
    for m in &exp.missing {
        o.warnings.push(format!("no input matched `{m}`"));
    }
    let opened: Vec<_> = pool.install(|| {
        exp.files
            .par_iter()
            .map(|p| open_one(&arts, p, opts))
            .collect()
    });
    let mut seen: HashMap<FileKey, PathBuf> = HashMap::new();
    for (path, r) in exp.files.iter().zip(opened) {
        match r {
            Ok(s) => {
                for w in s.open_warnings() {
                    o.warnings.push(format!("{}: {w}", path.display()));
                }
                let s = match seen.get(&s.key()) {
                    None => s,
                    Some(prev) if FileKey::same_content(prev, path).unwrap_or(false) => {
                        o.warnings.push(format!(
                            "{}: same content as {} (key {}), skipped",
                            path.display(),
                            prev.display(),
                            s.key()
                        ));
                        continue;
                    }
                    Some(prev) => {
                        // Different content, same sampled key: key this
                        // file by its whole content so ids stay unique.
                        let key = FileKey::of_file(path)?;
                        o.warnings.push(format!(
                            "{}: sampled key {} also used by {}; using full-content key {key}",
                            path.display(),
                            s.key(),
                            prev.display()
                        ));
                        let ko = ParseOptions {
                            key: Some(key),
                            ..opts.clone()
                        };
                        open_one(&arts, path, &ko)?
                    }
                };
                seen.entry(s.key()).or_insert_with(|| path.to_path_buf());
                o.sources.push(s);
            }
            Err(e) => {
                o.failed += 1;
                o.warnings.push(format!("{e:#}"));
            }
        }
    }
    o.bytes = o.sources.iter().map(|s| s.byte_len()).sum();
    let spans: Vec<Option<LogSpan>> =
        pool.install(|| o.sources.par_iter().map(|s| log_span(s.as_ref())).collect());
    o.warnings.extend(overlap_warnings(&o.sources, &spans));
    Ok(o)
}

/// A log's channel, computer and EventRecordID span, from its first and
/// last events.
#[derive(Debug, Clone, PartialEq)]
struct LogSpan {
    channel: String,
    computer: String,
    first: u64,
    last: u64,
}

/// `None` for non-logs, empty files, and files mixing hosts or channels
/// (forwarded events), where record ids of different logs interleave.
fn log_span(s: &dyn Source) -> Option<LogSpan> {
    if !s.is_log() {
        return None;
    }
    let mut first: Option<(String, String, u64)> = None;
    let mut last: Option<(String, String, u64)> = None;
    let grab = |ev: &crate::EventView<'_>| {
        (
            ev.channel.to_lowercase(),
            ev.computer.to_lowercase(),
            ev.event_record_id,
        )
    };
    for u in 0..s.units() {
        s.parse_unit(u, &mut |ev: &crate::EventView<'_>| {
            if first.is_none() {
                first = Some(grab(ev));
            }
        });
        if first.is_some() {
            break;
        }
    }
    for u in (0..s.units()).rev() {
        s.parse_unit(u, &mut |ev: &crate::EventView<'_>| last = Some(grab(ev)));
        if last.is_some() {
            break;
        }
    }
    let ((c1, h1, a), (c2, h2, b)) = (first?, last?);
    (c1 == c2 && h1 == h2 && a != 0 && b != 0).then(|| LogSpan {
        channel: c1,
        computer: h1,
        first: a.min(b),
        last: a.max(b),
    })
}

/// Two different files holding the same log (channel and computer) with
/// overlapping EventRecordIDs are likely two collections of it: their
/// common events would be counted twice.
fn overlap_warnings(sources: &[Arc<dyn Source>], spans: &[Option<LogSpan>]) -> Vec<String> {
    // (channel, computer) -> (first, last, source index)
    type Spans = Vec<(u64, u64, usize)>;
    let mut groups: HashMap<(&str, &str), Spans> = HashMap::new();
    for (i, sp) in spans.iter().enumerate() {
        if let Some(sp) = sp {
            groups
                .entry((&sp.channel, &sp.computer))
                .or_default()
                .push((sp.first, sp.last, i));
        }
    }
    let mut out = Vec::new();
    let mut keys: Vec<_> = groups.keys().copied().collect();
    keys.sort();
    for k in keys {
        let mut v = groups[&k].clone();
        v.sort();
        // The span reaching furthest so far: any later start below its end
        // overlaps it.
        let mut reach: Option<(u64, u64, usize)> = None;
        for (a, b, i) in v {
            if let Some((ra, rb, ri)) = reach
                && a <= rb
            {
                out.push(format!(
                    "{} and {}: the same log ({} on {}) with overlapping EventRecordIDs \
                     ({ra}-{rb} and {a}-{b}): likely two collections of it, events they share \
                     are counted twice",
                    sources[ri].path().display(),
                    sources[i].path().display(),
                    spans[i].as_ref().map_or("", |s| s.channel.as_str()),
                    spans[i].as_ref().map_or("", |s| s.computer.as_str()),
                ));
            }
            if reach.is_none_or(|(_, rb, _)| b > rb) {
                reach = Some((a, b, i));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_dirs_and_globs() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("host1/logs");
        std::fs::create_dir_all(&sub).unwrap();
        for n in ["Security.evtx", "System.EVTX", "notes.txt"] {
            std::fs::write(sub.join(n), b"x").unwrap();
        }
        let arts = crate::artifact::registry();
        let e = expand(&[d.path().display().to_string()], &arts).unwrap();
        assert_eq!(e.files.len(), 2);
        let g = format!("{}/**/Sec*.evtx", d.path().display());
        let e = expand(&[g], &arts).unwrap();
        assert_eq!(e.files.len(), 1);
        let e = expand(&["/nonexistent/x.evtx".into()], &arts).unwrap();
        assert_eq!(e.missing.len(), 1);
        // NTFS metadata found by name in a collection tree.
        let c = d.path().join("host1/C/$Extend");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(d.path().join("host1/C/$MFT"), b"x").unwrap();
        std::fs::write(c.join("$J"), b"x").unwrap();
        let e = expand(&[d.path().display().to_string()], &arts).unwrap();
        assert_eq!(e.files.len(), 4);
    }

    #[cfg(unix)]
    #[test]
    fn walk_follows_links_and_reports_unreadable_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("System.evtx"), b"x").unwrap();
        let col = d.path().join("collection");
        std::fs::create_dir_all(&col).unwrap();
        // A collection made of links (to files and to a folder).
        std::os::unix::fs::symlink(real.join("System.evtx"), col.join("Security.evtx")).unwrap();
        std::os::unix::fs::symlink(&real, col.join("linked")).unwrap();
        let locked = col.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("Sysmon.evtx"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let arts = crate::artifact::registry();
        let e = expand(&[col.display().to_string()], &arts).unwrap();
        // Root reads anything: then nothing is unreadable.
        let readable = std::fs::read_dir(&locked).is_ok();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(e.files.len(), 2, "{:?}", e.files);
        if !readable {
            assert_eq!(e.errors.len(), 1, "{:?}", e.errors);
            assert!(e.errors[0].contains("locked"), "{:?}", e.errors);
        }
    }
}
