//! `DateTime` handling utilities using the `time` crate.
//!
//! Provides a `DateTime` struct for working with timestamps, parsing,
//! formatting, and comparison operations in UTC.

use crate::error_constants::{ARITHMETIC_OVERFLOW, FAILED_EPOCH_CONVERSION};
use crate::errors::RustCommonUtilsError;
use derive_getters::Getters;
use std::ops::{Add, Sub};
use time::format_description::well_known::{Rfc2822, Rfc3339};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

const MONTH_NAMES: [(&str, &str); 12] = [
    ("January", "Jan"),
    ("February", "Feb"),
    ("March", "Mar"),
    ("April", "Apr"),
    ("May", "May"),
    ("June", "Jun"),
    ("July", "Jul"),
    ("August", "Aug"),
    ("September", "Sep"),
    ("October", "Oct"),
    ("November", "Nov"),
    ("December", "Dec"),
];

/// Supported datetime format types for parsing and conversion
#[derive(Clone, Debug, Copy)]
#[non_exhaustive]
pub enum DateTimeFormat {
    /// The format described in RFC 3339. `(i.e 1985-04-12T23:20:50.52Z)`
    Rfc3339,
    /// The format described in RFC 2822. `(i.e. Fri, 21 Nov 1997 09:55:06)`
    Rfc2822,
}

/// Convert format from string to `DateTimeFormat` enum
///
/// # Example
///
/// ```no_run
/// # use rust_sdk_common_utils::types::datetime::{DateTime, DateTimeFormat};
///
/// let dt = DateTime::parse("2025-10-21T14:30:00Z", DateTimeFormat::Rfc3339).unwrap();
/// ```
impl DateTimeFormat {
    pub fn from_string(format: &str) -> Result<DateTimeFormat, RustCommonUtilsError> {
        match format {
            "RFC3339" => Ok(DateTimeFormat::Rfc3339),
            "RFC2822" => Ok(DateTimeFormat::Rfc2822),
            _ => Err(RustCommonUtilsError::InvalidArguments {
                message: format!("Unsupported format type: {format}"),
            }),
        }
    }
}

/// A UTC datetime representation with nanosecond precision
///
/// `DateTime` provides a comprehensive datetime type supporting parsing, formatting,
/// arithmetic operations, and comparisons. All times are stored
/// and represented in UTC.
///
/// # Example
///
/// ```no_run
/// # use rust_sdk_common_utils::types::datetime::{DateTime, DateTimeFormat};
/// // Create from components
/// let dt = DateTime::new(2025, 10, 21, 14, 30, 0, 0);
/// println!("Year: {}, Month: {}", dt.year(), dt.month_str().unwrap());
///
/// // Parse from string
/// let parsed = DateTime::parse("2025-10-21T14:30:00Z", DateTimeFormat::Rfc3339).unwrap();
///
/// // Arithmetic operations
/// let later = &dt + 3600; // Add 1 hour
/// assert!(later > dt);
///
/// // Compare against current time
/// let current_time = DateTime::now().unwrap();
/// let is_future_time = current_time < dt;
///
/// // Format back to string
/// let formatted = dt.to_string(DateTimeFormat::Rfc3339).unwrap();
/// ```
#[derive(Clone, Debug, Getters, Copy)]
pub struct DateTime {
    /// Year (can be negative for BCE dates)
    year: i64,
    /// Month (1-12)
    month: u64,
    /// Day of month (1-31)
    day: u64,
    /// Hour (0-23)
    hour: u64,
    /// Minute (0-59)
    minute: u64,
    /// Second (0-59)
    second: u64,
    /// Nanosecond (0-999,999,999)
    nanosecond: i64,
}

#[allow(clippy::expect_used)]
impl PartialEq for DateTime {
    fn eq(&self, other: &Self) -> bool {
        self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION)
            == other.epoch_seconds().expect(FAILED_EPOCH_CONVERSION)
            && self.nanosecond == other.nanosecond
    }
}

impl Eq for DateTime {}

impl PartialOrd for DateTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(clippy::expect_used)]
impl Ord for DateTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.epoch_seconds()
            .expect(FAILED_EPOCH_CONVERSION)
            .cmp(&other.epoch_seconds().expect(FAILED_EPOCH_CONVERSION))
            .then(self.nanosecond.cmp(&other.nanosecond))
    }
}

/// Add epoch seconds to a `DateTime`
#[allow(clippy::expect_used)]
impl Add<i64> for DateTime {
    type Output = DateTime;

    fn add(self, seconds: i64) -> DateTime {
        DateTime::from_epoch_seconds(self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION) + seconds)
            .expect(ARITHMETIC_OVERFLOW)
    }
}

/// Add epoch seconds to a &`DateTime` (reference)
#[allow(clippy::expect_used)]
impl Add<i64> for &DateTime {
    type Output = DateTime;

    fn add(self, seconds: i64) -> DateTime {
        DateTime::from_epoch_seconds(self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION) + seconds)
            .expect(ARITHMETIC_OVERFLOW)
    }
}

/// Subtract epoch seconds from a `DateTime`
#[allow(clippy::expect_used)]
impl Sub<i64> for DateTime {
    type Output = DateTime;

    fn sub(self, seconds: i64) -> DateTime {
        DateTime::from_epoch_seconds(self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION) - seconds)
            .expect(ARITHMETIC_OVERFLOW)
    }
}

/// Subtract epoch seconds from a &`DateTime` (reference)
#[allow(clippy::expect_used)]
impl Sub<i64> for &DateTime {
    type Output = DateTime;

    fn sub(self, seconds: i64) -> DateTime {
        DateTime::from_epoch_seconds(self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION) - seconds)
            .expect(ARITHMETIC_OVERFLOW)
    }
}

/// Get difference between two `DateTime` objects in epoch seconds
#[allow(clippy::expect_used)]
impl Sub<DateTime> for DateTime {
    type Output = i64;

    fn sub(self, other: DateTime) -> i64 {
        self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION)
            - other.epoch_seconds().expect(FAILED_EPOCH_CONVERSION)
    }
}

/// Get difference between two &`DateTime` objects in epoch seconds
#[allow(clippy::expect_used)]
impl Sub<&DateTime> for &DateTime {
    type Output = i64;

    fn sub(self, other: &DateTime) -> i64 {
        self.epoch_seconds().expect(FAILED_EPOCH_CONVERSION)
            - other.epoch_seconds().expect(FAILED_EPOCH_CONVERSION)
    }
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::indexing_slicing)]
impl DateTime {
    /// Create a new `DateTime` from individual date and time components
    ///
    /// # Example
    ///
    /// ``` no_run
    /// # use rust_sdk_common_utils::types::datetime::DateTime;
    ///
    /// // Create New Year's Day 2025 at noon
    /// let dt = DateTime::new(2025, 1, 1, 12, 0, 0, 0);
    /// ```
    pub const fn new(
        year: i64,
        month: u64,
        day: u64,
        hour: u64,
        minute: u64,
        second: u64,
        nanosecond: i64,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        }
    }

    /// Create a `DateTime` from Unix epoch seconds
    /// # Example
    ///
    /// ```no_run
    /// # use rust_sdk_common_utils::types::datetime::DateTime;
    ///
    /// // Unix epoch (January 1, 1970)
    /// let dt = DateTime::from_epoch_seconds(0).unwrap();
    /// ```
    pub fn from_epoch_seconds(epoch_seconds: i64) -> Result<DateTime, RustCommonUtilsError> {
        let odt = OffsetDateTime::from_unix_timestamp(epoch_seconds)?;
        Ok(Self::from_offset_datetime(odt))
    }

    /// Create a `DateTime` from epoch time split into seconds and nanoseconds
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_sdk_common_utils::types::datetime::DateTime;
    ///
    /// // 1 second + 500 million nanoseconds (0.5 seconds)
    /// let dt = DateTime::from_epoch_nanos(1, 500_000_000).unwrap();
    /// ```
    pub fn from_epoch_nanos(
        seconds_portion: i64,
        nanos_portion: i64,
    ) -> Result<DateTime, RustCommonUtilsError> {
        if !(0..=999_999_999).contains(&nanos_portion) {
            return Err(RustCommonUtilsError::InvalidArguments {
                message: format!("Invalid nanos portion: {nanos_portion}. Must be 0-999,999,999"),
            });
        }

        let odt = OffsetDateTime::from_unix_timestamp_nanos(i128::from(
            seconds_portion * 1_000_000_000 + nanos_portion,
        ))?;

        Ok(Self::from_offset_datetime(odt))
    }

    /// Return the current `DateTime` in UTC truncated to seconds
    pub fn now() -> Result<DateTime, RustCommonUtilsError> {
        let odt = OffsetDateTime::now_utc();
        Self::from_epoch_seconds(odt.unix_timestamp())
    }

    /// Return the current `DateTime` in UTC to the nearest nanosecond
    pub fn now_nanos() -> DateTime {
        let odt = OffsetDateTime::now_utc();
        Self::from_offset_datetime(odt)
    }

    /// Returns this `DateTime` in seconds since Unix epoch
    pub fn epoch_seconds(&self) -> Result<i64, RustCommonUtilsError> {
        Ok(self.to_offset_datetime()?.unix_timestamp())
    }

    /// Returns the subsecond component in nanoseconds
    pub const fn nanos(&self) -> i64 {
        self.nanosecond
    }

    // Full month name (i.e. January)
    pub fn month_str(&self) -> Result<String, RustCommonUtilsError> {
        match self.month {
            1..=12 => {
                let (long, _) = MONTH_NAMES[self.month as usize - 1];
                Ok(long.to_string())
            }
            _ => Err(RustCommonUtilsError::InvalidArguments {
                message: format!("Invalid month: {}. Must be 1-12", self.month),
            }),
        }
    }

    // Short month name (i.e. Jan)
    pub fn month_str_short(&self) -> Result<String, RustCommonUtilsError> {
        match self.month {
            1..=12 => {
                let (_, short) = MONTH_NAMES[self.month as usize - 1];
                Ok(short.to_string())
            }
            _ => Err(RustCommonUtilsError::InvalidArguments {
                message: format!("Invalid month: {}. Must be 1-12", self.month),
            }),
        }
    }

    /// Parse `DateTime` from string using the specified format
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_sdk_common_utils::types::datetime::{DateTime, DateTimeFormat};
    ///
    /// let dt = DateTime::parse("2025-10-21T14:30:00Z", DateTimeFormat::Rfc3339).unwrap();
    /// ```
    #[allow(unreachable_patterns)] // enum is non-exhaustive so "unreachable" warning is incorrect
    pub fn parse(s: &str, format: DateTimeFormat) -> Result<DateTime, RustCommonUtilsError> {
        match format {
            DateTimeFormat::Rfc3339 => {
                let odt = OffsetDateTime::parse(s, &Rfc3339).map_err(|e| {
                    RustCommonUtilsError::ParseError {
                        message: format!("Failed to parse RFC3339 datetime from '{s}': {e}"),
                    }
                })?;
                Ok(Self::from_offset_datetime(odt))
            }
            DateTimeFormat::Rfc2822 => {
                let odt = OffsetDateTime::parse(s, &Rfc2822).map_err(|e| {
                    RustCommonUtilsError::ParseError {
                        message: format!("Failed to parse RFC2822 datetime from '{s}': {e}"),
                    }
                })?;
                Ok(Self::from_offset_datetime(odt))
            }

            _ => Err(RustCommonUtilsError::InvalidArguments {
                message: format!("Unsupported format type: {format:?}"),
            }),
        }
    }

    /// Format `DateTime` as a string
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_sdk_common_utils::types::datetime::{DateTime, DateTimeFormat};
    ///
    /// let dt = DateTime::new(2025, 10, 21, 14, 30, 0, 0);
    /// let formatted = dt.to_string(DateTimeFormat::Rfc3339).unwrap();
    /// ```
    #[allow(unreachable_patterns)] // enum is non-exhaustive so "unreachable" warning is incorrect
    pub fn to_string(&self, format: DateTimeFormat) -> Result<String, RustCommonUtilsError> {
        match format {
            DateTimeFormat::Rfc3339 => self.to_offset_datetime()?.format(&Rfc3339).map_err(|e| {
                RustCommonUtilsError::FormatError {
                    message: format!("Failed to format datetime as RFC3339: {e}"),
                }
            }),

            DateTimeFormat::Rfc2822 => self.to_offset_datetime()?.format(&Rfc2822).map_err(|e| {
                RustCommonUtilsError::FormatError {
                    message: format!("Failed to format datetime as RFC2822: {e}"),
                }
            }),

            _ => Err(RustCommonUtilsError::InvalidArguments {
                message: format!("Unsupported format type: {format:?}"),
            }),
        }
    }

    /// Helper to convert from `time::OffsetDateTime`
    #[allow(clippy::cast_lossless)]
    fn from_offset_datetime(odt: OffsetDateTime) -> DateTime {
        let date = odt.date();
        let time = odt.time();

        Self::new(
            i64::from(date.year()),
            date.month() as u64,
            date.day() as u64,
            time.hour() as u64,
            time.minute() as u64,
            time.second() as u64,
            time.nanosecond() as i64,
        )
    }

    /// Helper to convert to `time::OffsetDateTime`
    #[allow(clippy::cast_sign_loss)]
    fn to_offset_datetime(self) -> Result<OffsetDateTime, RustCommonUtilsError> {
        let month = Month::try_from(self.month as u8)?;
        let date = Date::from_calendar_date(self.year as i32, month, self.day as u8)?;
        let time = Time::from_hms_nano(
            self.hour as u8,
            self.minute as u8,
            self.second as u8,
            self.nanosecond as u32,
        )?;

        Ok(PrimitiveDateTime::new(date, time).assume_utc())
    }
}
