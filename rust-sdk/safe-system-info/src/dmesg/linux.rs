use super::common::{DmesgEntry, DmesgProvider};
use crate::RustSysteminfoError;
use crate::options::DmesgOptions;
use chrono::{DateTime, Local};
use rmesg::Backend;
use std::time::{Duration, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub(crate) struct Dmesg;

impl DmesgProvider for Dmesg {
    fn dmesg_info(&self, options: DmesgOptions) -> Result<Vec<DmesgEntry>, RustSysteminfoError> {
        let entries = rmesg::log_entries(Backend::DevKMsg, false)?;
        parse_dmesg_entries(entries, options)
    }
}

fn format_human_readable_timestamp(
    timestamp_duration: Duration,
) -> Result<String, RustSysteminfoError> {
    let boot_time_secs = procfs::boot_time_secs()?;

    let boot_time = UNIX_EPOCH + Duration::from_secs(boot_time_secs);
    let entry_time = boot_time + timestamp_duration;

    let datetime = DateTime::<Local>::from(entry_time);
    Ok(datetime.format("%a %b %d %H:%M:%S %Y").to_string())
}

fn format_system_start_timestamp(timestamp_duration: Duration) -> String {
    let total_seconds = timestamp_duration.as_secs_f64();
    format!("{total_seconds:>12.6}")
}

fn parse_dmesg_entries<T: DmesgEntryTrait>(
    raw_entries: Vec<T>,
    options: DmesgOptions,
) -> Result<Vec<DmesgEntry>, RustSysteminfoError> {
    let mut dmesg_entries = Vec::new();

    for entry in raw_entries {
        let Some(timestamp_duration) = entry.get_timestamp() else {
            continue;
        };

        if entry.get_message().is_empty() {
            continue;
        }

        let timestamp_str = if options.human_readable_time {
            format_human_readable_timestamp(timestamp_duration)?
        } else {
            format_system_start_timestamp(timestamp_duration)
        };

        dmesg_entries.push(DmesgEntry {
            timestamp_from_system_start: timestamp_str,
            message: entry.get_message().to_string(),
        });
    }

    Ok(dmesg_entries)
}

trait DmesgEntryTrait {
    fn get_timestamp(&self) -> Option<Duration>;
    fn get_message(&self) -> &str;
}

impl DmesgEntryTrait for rmesg::entry::Entry {
    fn get_timestamp(&self) -> Option<Duration> {
        self.timestamp_from_system_start
    }
    fn get_message(&self) -> &str {
        &self.message
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct MockDmesgEntry {
        timestamp: Option<Duration>,
        message: String,
    }

    impl DmesgEntryTrait for MockDmesgEntry {
        fn get_timestamp(&self) -> Option<Duration> {
            self.timestamp
        }
        fn get_message(&self) -> &str {
            &self.message
        }
    }

    /// Given: a duration with nanosecond precision
    /// When: format_system_start_timestamp is called
    /// Then: returns properly formatted timestamp string
    #[test]
    fn test_format_system_start_timestamp_with_duration() {
        let duration = Duration::from_nanos(123_456_789_000);
        let result = format_system_start_timestamp(duration);
        assert_eq!(result, "  123.456789");
    }

    /// Given: a duration of 60 seconds
    /// When: format_human_readable_timestamp is called
    /// Then: returns a non-empty human readable timestamp
    #[test]
    fn test_format_human_readable_timestamp() {
        let duration = Duration::from_secs(60);
        let result = format_human_readable_timestamp(duration);
        assert!(result.is_ok());
        // The exact format will depend on boot time, but we can verify it's not empty
        assert!(!result.unwrap().is_empty());
    }

    /// Given: a duration with microsecond precision
    /// When: format_system_start_timestamp is called
    /// Then: returns timestamp rounded to 6 decimal places
    #[test]
    fn test_format_system_start_timestamp_precision() {
        let duration = Duration::from_nanos(1_234_567_890);
        let result = format_system_start_timestamp(duration);
        assert_eq!(result, "    1.234568");
    }

    /// Given: a zero duration
    /// When: format_system_start_timestamp is called
    /// Then: returns zero timestamp with proper formatting
    #[test]
    fn test_format_system_start_timestamp_zero() {
        let duration = Duration::from_secs(0);
        let result = format_system_start_timestamp(duration);
        assert_eq!(result, "    0.000000");
    }

    /// Given: a large duration value
    /// When: format_system_start_timestamp is called
    /// Then: returns properly formatted large timestamp
    #[test]
    fn test_format_system_start_timestamp_large_value() {
        let duration = Duration::from_secs(12345);
        let result = format_system_start_timestamp(duration);
        assert_eq!(result, "12345.000000");
    }

    /// Given: mock entries with no timestamp and valid entries
    /// When: parse_dmesg_entries is called
    /// Then: entries with no timestamp are filtered out
    #[test]
    fn test_parse_entries_filters_no_timestamp() {
        let mock_entries = vec![
            MockDmesgEntry {
                timestamp: None,
                message: "should be filtered out".to_string(),
            },
            MockDmesgEntry {
                timestamp: Some(Duration::from_secs(123)),
                message: "should be kept".to_string(),
            },
        ];

        let options = DmesgOptions {
            human_readable_time: false,
        };
        let result = parse_dmesg_entries(mock_entries, options).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].message, "should be kept");
    }

    /// Given: mock entries with empty messages and valid entries  
    /// When: parse_dmesg_entries is called
    /// Then: entries with empty messages are filtered out
    #[test]
    fn test_parse_entries_filters_empty_messages() {
        let mock_entries = vec![
            MockDmesgEntry {
                timestamp: Some(Duration::from_secs(123)),
                message: "".to_string(),
            },
            MockDmesgEntry {
                timestamp: Some(Duration::from_secs(456)),
                message: "valid message".to_string(),
            },
        ];

        let options = DmesgOptions {
            human_readable_time: false,
        };
        let result = parse_dmesg_entries(mock_entries, options).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].message, "valid message");
    }

    /// Given: mock entries with system start timestamp option
    /// When: parse_dmesg_entries is called with human_readable_time=false
    /// Then: returns entries with system start timestamp format
    #[test]
    fn test_parse_entries_system_start_timestamps() {
        let mock_entries = vec![MockDmesgEntry {
            timestamp: Some(Duration::from_secs(123)),
            message: "test message".to_string(),
        }];

        let options = DmesgOptions {
            human_readable_time: false,
        };
        let result = parse_dmesg_entries(mock_entries, options).unwrap();

        assert_eq!(result[0].timestamp_from_system_start, "  123.000000");
        assert_eq!(result[0].message, "test message");
    }

    /// Given: mock entries with human readable timestamp option
    /// When: parse_dmesg_entries is called with human_readable_time=true
    /// Then: returns entries with human readable timestamp format
    #[test]
    fn test_parse_entries_human_readable_timestamps() {
        let mock_entries = vec![MockDmesgEntry {
            timestamp: Some(Duration::from_secs(60)),
            message: "boot message".to_string(),
        }];

        let options = DmesgOptions {
            human_readable_time: true,
        };
        let result = parse_dmesg_entries(mock_entries, options).unwrap();

        assert!(!result[0].timestamp_from_system_start.contains("60.000000"));
        assert!(result[0].timestamp_from_system_start.len() > 10);
        assert_eq!(result[0].message, "boot message");
    }

    /// Given: empty input vector
    /// When: parse_dmesg_entries is called
    /// Then: returns empty result vector
    #[test]
    fn test_parse_entries_empty_input() {
        let mock_entries: Vec<MockDmesgEntry> = vec![];
        let options = DmesgOptions {
            human_readable_time: false,
        };
        let result = parse_dmesg_entries(mock_entries, options).unwrap();

        assert_eq!(result.len(), 0);
    }

    /// Given: mock entries where all should be filtered out
    /// When: parse_dmesg_entries is called  
    /// Then: returns empty result vector
    #[test]
    fn test_parse_entries_all_filtered() {
        let mock_entries = vec![
            MockDmesgEntry {
                timestamp: None,
                message: "no timestamp".to_string(),
            },
            MockDmesgEntry {
                timestamp: Some(Duration::from_secs(123)),
                message: "".to_string(),
            },
        ];

        let options = DmesgOptions {
            human_readable_time: false,
        };
        let result = parse_dmesg_entries(mock_entries, options).unwrap();

        assert_eq!(result.len(), 0);
    }
}
