//! Core of Forensic Hunter: the event model, artifact parsers, filters and the
//! parallel engine that drives them.
//!
//! The design keeps a single hot path: an artifact [`Source`](artifact::Source)
//! splits its input into independent units (EVTX chunks, runs of MFT
//! records, journal blocks, one prefetch file), the
//! [`engine`] runs units on a rayon pool and hands each decoded
//! [`EventView`](event::EventView) to a caller-supplied closure while it still
//! borrows the decoder's buffer. Nothing is materialised unless the caller
//! keeps it.

pub mod artifact;
pub mod engine;
pub mod event;
pub mod evtx;
pub mod filter;
pub mod id;
pub mod input;
pub(crate) mod io;
pub mod normalize;
pub mod ntfs;
pub mod prefetch;
pub mod time;

pub use artifact::{Artifact, Source, UnitReport};
pub use event::{EventView, Field, Val};
pub use filter::Filter;
pub use id::{EventRef, FileKey};
pub use time::Ts;
