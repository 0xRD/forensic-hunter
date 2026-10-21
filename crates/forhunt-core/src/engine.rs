//! Parallel, order-preserving execution of parse units.
//!
//! Units from all sources are flattened into one task list (file order, then
//! unit order) and run on a rayon pool with a bounded number in flight.
//! Results are handed to the consumer strictly in task order, so output is
//! identical whatever the thread count, and memory stays bounded by the
//! window size whatever the input size.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::artifact::Source;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnitId {
    pub source: usize,
    pub unit: usize,
}

pub struct Engine<'p> {
    pool: &'p rayon::ThreadPool,
    window: usize,
}

impl<'p> Engine<'p> {
    pub fn new(pool: &'p rayon::ThreadPool) -> Self {
        Engine {
            pool,
            window: pool.current_num_threads().max(1) * 4,
        }
    }

    pub fn window(mut self, w: usize) -> Self {
        self.window = w.max(1);
        self
    }

    /// Runs `work` on every unit and passes results to `consume` in order.
    /// Setting `stop` prevents new units from starting; units already running
    /// finish and are still delivered.
    pub fn run<P, W, C>(&self, sources: &[Arc<dyn Source>], stop: &AtomicBool, work: W, consume: C)
    where
        P: Send,
        W: Fn(UnitId, &dyn Source) -> P + Sync,
        C: FnMut(UnitId, P),
    {
        let tasks: Vec<UnitId> = sources
            .iter()
            .enumerate()
            .flat_map(|(i, s)| (0..s.units()).map(move |u| UnitId { source: i, unit: u }))
            .collect();
        self.run_tasks(sources, &tasks, stop, work, consume)
    }

    /// Like [`Engine::run`] on an explicit task list.
    pub fn run_tasks<P, W, C>(
        &self,
        sources: &[Arc<dyn Source>],
        tasks: &[UnitId],
        stop: &AtomicBool,
        work: W,
        mut consume: C,
    ) where
        P: Send,
        W: Fn(UnitId, &dyn Source) -> P + Sync,
        C: FnMut(UnitId, P),
    {
        if self.pool.current_num_threads() <= 1 || tasks.len() <= 1 {
            for &t in tasks {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let p = work(t, sources[t.source].as_ref());
                consume(t, p);
            }
            return;
        }
        let (tx, rx) = crossbeam_channel::unbounded::<(usize, std::thread::Result<P>)>();
        let work = &work;
        self.pool.in_place_scope(|s| {
            let mut next = 0usize;
            let mut next_yield = 0usize;
            let mut in_flight = 0usize;
            let mut reorder: BTreeMap<usize, std::thread::Result<P>> = BTreeMap::new();
            loop {
                while in_flight < self.window && next < tasks.len() && !stop.load(Ordering::Relaxed)
                {
                    let seq = next;
                    let t = tasks[seq];
                    let tx = tx.clone();
                    let src = sources[t.source].as_ref();
                    s.spawn(move |_| {
                        let r = catch_unwind(AssertUnwindSafe(|| work(t, src)));
                        let _ = tx.send((seq, r));
                    });
                    next += 1;
                    in_flight += 1;
                }
                if let Some(r) = reorder.remove(&next_yield) {
                    match r {
                        Ok(p) => consume(tasks[next_yield], p),
                        Err(e) => resume_unwind(e),
                    }
                    next_yield += 1;
                    continue;
                }
                if in_flight == 0 {
                    break;
                }
                let (seq, r) = rx.recv().expect("workers hold a sender");
                in_flight -= 1;
                reorder.insert(seq, r);
            }
        });
    }
}

/// Builds the worker pool. `0` threads means one per physical core.
pub fn build_pool(threads: usize, physical_cores: usize) -> anyhow::Result<rayon::ThreadPool> {
    let n = if threads == 0 {
        physical_cores.max(1)
    } else {
        threads
    };
    Ok(rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .thread_name(|i| format!("forhunt-{i}"))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Sink, UnitReport};
    use crate::id::FileKey;
    use std::path::{Path, PathBuf};

    struct Fake(usize, PathBuf);
    impl Source for Fake {
        fn key(&self) -> FileKey {
            FileKey(0)
        }
        fn path(&self) -> &Path {
            &self.1
        }
        fn units(&self) -> usize {
            self.0
        }
        fn byte_len(&self) -> u64 {
            0
        }
        fn parse_unit(&self, _: usize, _: &mut dyn Sink) -> UnitReport {
            UnitReport::default()
        }
    }

    #[test]
    fn ordered_for_any_thread_count() {
        let sources: Vec<Arc<dyn Source>> = vec![
            Arc::new(Fake(37, "a".into())),
            Arc::new(Fake(0, "b".into())),
            Arc::new(Fake(51, "c".into())),
        ];
        for threads in [1, 2, 4, 8] {
            let pool = build_pool(threads, 1).unwrap();
            let mut seen = Vec::new();
            let stop = AtomicBool::new(false);
            Engine::new(&pool).window(3).run(
                &sources,
                &stop,
                |u, _| {
                    // Uneven work to shuffle completion order.
                    std::thread::sleep(std::time::Duration::from_micros(
                        ((u.unit * 7919) % 13) as u64 * 50,
                    ));
                    (u.source, u.unit)
                },
                |u, p| {
                    assert_eq!((u.source, u.unit), p);
                    seen.push(p);
                },
            );
            assert_eq!(seen.len(), 88);
            assert!(seen.windows(2).all(|w| w[0] < w[1]));
        }
    }
}
