//! Expands command-line paths (files, directories, globs) into a sorted,
//! de-duplicated list of artifact files.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::artifact::Artifact;

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
    }
}
