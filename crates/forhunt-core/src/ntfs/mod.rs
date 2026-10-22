//! NTFS metadata artifacts: the master file table (`$MFT`) and the change
//! journal (`$UsnJrnl:$J`).

pub mod mft;
mod paths;
mod record;
pub mod usn;

pub use mft::{MftArtifact, MftSource};
pub use usn::{UsnArtifact, UsnSource};
