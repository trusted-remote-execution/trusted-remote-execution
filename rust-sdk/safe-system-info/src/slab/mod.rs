#[cfg(target_os = "linux")]
mod common;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod parser;

// public re-exports
#[cfg(target_os = "linux")]
pub use common::{SlabEntry, SlabInfo, SlabSummary};

// pub(crate) re-exports
#[cfg(target_os = "linux")]
pub(crate) use common::SlabInfoProvider;
#[cfg(target_os = "linux")]
pub(crate) use linux::Slab;
