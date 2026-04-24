//! `seq` - Generate numeric sequences
//!
//! # Example (Rhai)
//! ```rhai
//! // Generate 1..10
//! let nums = seq(1, 10);
//!
//! // Generate with step
//! let nums = seq([seq::step(2)], 1, 10);  // [1, 3, 5, 7, 9]
//! ```

use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, find_flag_value};
use rust_safe_io::errors::RustSafeIoError;

/// Flags for the `seq` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `seq::step(n)` — increment by n (default 1)
#[derive(Debug, Clone)]
pub(crate) enum SeqFlag {
    Step(i64),
}

pub(crate) struct SeqOptions {
    pub step: i64,
}

impl SeqOptions {
    pub(crate) fn from_flags(flags: &[SeqFlag]) -> Self {
        Self {
            step: find_flag_value(flags, |f| match f {
                SeqFlag::Step(n) => Some(*n),
            })
            .unwrap_or(1),
        }
    }
}

/// Generate a numeric sequence from start to end (inclusive)
pub(crate) fn seq(start: i64, end: i64) -> Result<Vec<i64>, RustSafeIoError> {
    seq_with_flags(start, end, &Array::new())
}

/// Generate a numeric sequence with user-provided flags
pub(crate) fn seq_with_flags(
    start: i64,
    end: i64,
    flags_arr: &Array,
) -> Result<Vec<i64>, RustSafeIoError> {
    let flags = extract_flags::<SeqFlag>(flags_arr)?;
    let opts = SeqOptions::from_flags(&flags);

    if opts.step == 0 {
        return Err(RustSafeIoError::InvalidArguments {
            reason: "seq: step cannot be zero".to_string(),
        });
    }

    let mut result = Vec::new();
    if opts.step > 0 {
        let mut i = start;
        while i <= end {
            result.push(i);
            i += opts.step;
        }
    } else {
        let mut i = start;
        while i >= end {
            result.push(i);
            i += opts.step;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;

    /// Given: A start and end value
    /// When: Calling seq
    /// Then: A sequence from start to end is returned
    #[test]
    fn test_seq_basic() {
        let result = seq(1, 5).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    /// Given: A step of 2
    /// When: Calling seq_with_flags
    /// Then: Every other number is returned
    #[test]
    fn test_seq_with_step() {
        let flags: Array = vec![Dynamic::from(SeqFlag::Step(2))];
        let result = seq_with_flags(1, 10, &flags).unwrap();
        assert_eq!(result, vec![1, 3, 5, 7, 9]);
    }

    /// Given: A step of 0
    /// When: Calling seq_with_flags
    /// Then: An error is returned
    #[test]
    fn test_seq_zero_step_error() {
        let flags: Array = vec![Dynamic::from(SeqFlag::Step(0))];
        let result = seq_with_flags(1, 10, &flags);
        assert!(result.is_err());
    }

    /// Given: A negative step
    /// When: Calling seq_with_flags with start > end
    /// Then: A descending sequence is returned
    #[test]
    fn test_seq_negative_step() {
        let flags: Array = vec![Dynamic::from(SeqFlag::Step(-1))];
        let result = seq_with_flags(5, 1, &flags).unwrap();
        assert_eq!(result, vec![5, 4, 3, 2, 1]);
    }

    /// Given: An array with a non-SeqFlag element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_seq_rejects_wrong_flag_type() {
        let flags: Array = vec![Dynamic::from("not_a_flag")];
        let result = seq_with_flags(1, 5, &flags);
        assert!(result.is_err());
    }
}
