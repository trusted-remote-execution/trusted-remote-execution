use serde_derive::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};

/// # Units
/// * `COUNT`: Represents a count value
/// * `TIME`: Represents time value in nanoseconds
#[derive(
    Display, EnumString, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy, EnumIter,
)]
#[non_exhaustive]
#[repr(i32)]
pub enum MetricUnitType {
    UNDEFINED = 0,
    COUNT = 1,
    TIME = 2,
    MEGABYTES = 3,
    PERCENT = 4,
}
