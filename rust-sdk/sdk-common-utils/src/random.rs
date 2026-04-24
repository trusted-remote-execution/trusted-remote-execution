//! Utility functions for common operations.

use rand::distr::{Alphanumeric, SampleString};
use rand::rng;

/// # Example
///
/// ```no_run
/// # use rust_sdk_common_utils::random::random_alphanumeric;
///
/// // Generate a random 10-character string for a temporary file name
/// let tmp_filename = format!("tmp.{}", random_alphanumeric(10)); // "tmp.WksppE3et4"
///
/// ```
// [REX-2342] This function will be kept until it get added to rhai-rand crate
pub fn random_alphanumeric(length: i64) -> String {
    let length_usize = usize::try_from(length).unwrap_or(16);
    Alphanumeric.sample_string(&mut rng(), length_usize)
}
