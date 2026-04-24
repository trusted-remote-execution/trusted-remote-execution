use std::time::Instant;

/// Calculates the elapsed time in nanoseconds since the provided start time.
///
/// This function computes the duration between the provided start time and the current
/// time, returning the result as nanoseconds in floating-point format. The casting is
/// acceptable as it allows capturing elapsed time over 100 days with sufficient precision.
///
/// # Example
/// ```no_run
/// # use rex_runner::utils::elapsed_duration;
/// # use std::time::Instant;
/// # use std::thread;
/// # use std::time::Duration;
/// # let start = Instant::now();
/// # thread::sleep(Duration::from_millis(100));
/// let elapsed_ns = elapsed_duration(&start);
/// println!("Elapsed time: {} nanoseconds", elapsed_ns);
/// ```
#[allow(clippy::cast_precision_loss)]
pub fn elapsed_duration(start_time: &Instant) -> f64 {
    start_time.elapsed().as_nanos() as f64
}
