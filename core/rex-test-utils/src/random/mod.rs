use rand::distr::{Alphanumeric, SampleString};

/// Generates a random alphanumeric string with length 16.
///
/// # Returns
/// * `String` - A random alphanumeric string with length 16
///
///
pub fn get_rand_string() -> String {
    get_rand_string_of_len(16)
}

/// Generates a random alphanumeric string with the specified input length.
///
/// # Returns
/// * `String` - A random alphanumeric string with the specified input length
///
///
pub fn get_rand_string_of_len(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}
