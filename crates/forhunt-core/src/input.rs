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
    let claimed = |p: &Path| artifacts.iter().any(|a| a.matches_name(p));
    for arg in args {
        let p = Path::new(arg);
        if p.is_file() {
            out.insert(p.to_path_buf());
        } else if p.is_dir() {
            let before = out.len();
            walk(p, &mut |f| {
                if claimed(f) {
                    out.insert(f.to_path_buf());
                }
            });
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
            walk(&base, &mut |f| {
                if glob.is_match(f) || f.strip_prefix("./").is_ok_and(|s| glob.is_match(s)) {
                    out.insert(f.to_path_buf());
                }
            });
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

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) {
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
    {
        let Ok(entry) = entry else { continue };
        if entry.file_type().is_file() {
            f(entry.path());
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
    Ok(o)
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
}
