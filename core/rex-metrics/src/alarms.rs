use derive_builder::Builder;
use serde_derive::{Deserialize, Serialize};

/// Represents an alarm in the REX components.
///
/// # Fields
/// * `alarm_type` - The type identifier for the alarm
/// * `alarm_details` - Optional details providing more context about the alarm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct RexAlarm {
    pub alarm_type: String,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarm_details: Option<String>,
}

/// Registry for collecting and managing REX alarms.
#[derive(Builder, Debug, Default, Clone)]
#[builder(derive(Debug))]
pub struct RexAlarmRegistry {
    #[builder(default)]
    alarms: Vec<RexAlarm>,
}

impl RexAlarmRegistry {
    /// Adds a new alarm to the `RexAlarmRegistry` registry.
    ///
    /// # Arguments
    /// * `rex_alarm` - The Rex Alarm to add built using `RexAlarmBuilder`
    ///
    /// # Example
    /// ```
    /// use rex_metrics_and_alarms::alarms::{RexAlarmRegistryBuilder, RexAlarmBuilder};
    ///
    /// let mut rex_alarm_registry = RexAlarmRegistryBuilder::default().build().unwrap();
    ///
    /// let rex_alarm = RexAlarmBuilder::default()
    ///     .alarm_type("HighCPU".to_string())
    ///     .alarm_details(Some("90% usage".to_string()))
    ///     .build()
    ///     .unwrap();
    /// rex_alarm_registry.add_alarm(rex_alarm);
    ///
    ///
    /// let rex_alarm = RexAlarmBuilder::default()
    ///     .alarm_type("LowMemory".to_string())
    ///     .build()
    ///     .unwrap();
    /// rex_alarm_registry.add_alarm(rex_alarm);
    /// ```
    pub fn add_alarm(&mut self, rex_alarm: RexAlarm) {
        self.alarms.push(rex_alarm);
    }

    /// Returns the vector of alarms in the registry.
    ///
    /// # Example
    /// ```
    /// use rex_metrics_and_alarms::alarms::{RexAlarmRegistryBuilder, RexAlarmBuilder};
    ///
    /// let mut rex_alarm_registry = RexAlarmRegistryBuilder::default().build().unwrap();
    /// let rex_alarm = RexAlarmBuilder::default()
    ///     .alarm_type("HighCPU".to_string())
    ///     .alarm_details(Some("90% usage".to_string()))
    ///     .build()
    ///     .unwrap();
    /// rex_alarm_registry.add_alarm(rex_alarm);
    /// let rex_alarms = rex_alarm_registry.get_alarms();
    /// ```
    pub fn get_alarms(&self) -> Option<&Vec<RexAlarm>> {
        (!self.alarms.is_empty()).then_some(&self.alarms)
    }

    /// Takes and clears all alarms from the registry
    pub fn take_alarms(&mut self) -> Option<Vec<RexAlarm>> {
        (!self.alarms.is_empty()).then(|| std::mem::take(&mut self.alarms))
    }
}

/// Creates and registers a new alarm in the alarm registry
///
/// # Note
/// * Arguments in this method can change during future changes.
///   To avoid breaking changes, use `add_alarm` directly.
///
/// # Panics
/// * This method will never panic since we explicitly provide the required field `alarm_type` for `RexAlarm`
#[allow(clippy::unwrap_used)]
pub fn build_rex_alarm(alarm_type: String, alarm_details: Option<String>) -> RexAlarm {
    RexAlarmBuilder::default()
        .alarm_type(alarm_type)
        .alarm_details(alarm_details)
        .build()
        .unwrap()
}

/// Shared registry module providing thread-safe alarm registry functionality.
/// This module is only available when the `shared-registry` feature is enabled.
#[cfg(feature = "shared-registry")]
pub mod shared {
    use super::{RexAlarm, RexAlarmRegistryBuilder};
    use anyhow::Error;
    use std::sync::{Arc, Mutex};

    /// Concurrent version of the `RexAlarmRegistry` that can be safely shared across threads using Arc<Mutex<>>.
    pub type SharedRexAlarmRegistry = Arc<Mutex<super::RexAlarmRegistry>>;

    /// Creates a new concurrent `RexAlarmRegistry` that can be safely shared across threads.
    pub fn create_rex_alarm_registry() -> Result<SharedRexAlarmRegistry, Error> {
        Ok(RexAlarmRegistryBuilder::default()
            .build()
            .map(|registry| Arc::new(Mutex::new(registry)))?)
    }

    /// Adds a new alarm to a concurrent `RexAlarmRegistry`
    ///
    /// # Errors
    /// Recovers from the poisoned mutex and adds the alarm
    ///
    /// # Example
    /// ```
    /// use rex_metrics_and_alarms::alarms::build_rex_alarm;
    /// use rex_metrics_and_alarms::alarms::shared::{create_rex_alarm_registry, add_alarm_to_rex_registry};
    ///
    /// let registry = create_rex_alarm_registry().unwrap();
    /// let alarm = build_rex_alarm("HighCPU".to_string(), Some("90% usage".to_string()));
    /// add_alarm_to_rex_registry(&registry, alarm);
    /// ```
    pub fn add_alarm_to_rex_registry(registry: &SharedRexAlarmRegistry, alarm: RexAlarm) {
        match registry.lock() {
            Ok(mut guard) => guard.add_alarm(alarm),
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.add_alarm(alarm);
            }
        }
    }

    /// Gets alarms from the concurrent `RexAlarmRegistry`
    ///
    /// # Errors
    /// Recovers from the poisoned mutex and returns the alarms in the registry
    ///
    /// # Returns
    /// * `Option<Vec<RexAlarm>>` - The alarms in the registry, or None if the registry is empty
    ///
    /// # Example
    /// ```
    /// use rex_metrics_and_alarms::alarms::build_rex_alarm;
    /// use rex_metrics_and_alarms::alarms::shared::{create_rex_alarm_registry, add_alarm_to_rex_registry, get_alarms_from_rex_registry};
    ///
    /// let registry = create_rex_alarm_registry().unwrap();
    /// let alarm = build_rex_alarm("HighCPU".to_string(), Some("90% usage".to_string()));
    /// add_alarm_to_rex_registry(&registry, alarm);
    /// let alarms = get_alarms_from_rex_registry(&registry);
    /// ```
    pub fn get_alarms_from_rex_registry(
        registry: &SharedRexAlarmRegistry,
    ) -> Option<Vec<RexAlarm>> {
        match registry.lock() {
            Ok(guard) => guard.get_alarms().cloned(),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                guard.get_alarms().cloned()
            }
        }
    }

    /// Builds a `RexAlarm` and add it to a `RexAlarmRegistry` concurrent registry
    ///
    /// # Note
    /// * Arguments in this method can change during future changes.
    ///   To avoid breaking changes, use `add_alarm` directly.
    ///
    /// # Example
    /// ```
    /// use rex_metrics_and_alarms::alarms::shared::{create_rex_alarm_registry, register_alarm};
    ///
    /// let registry = create_rex_alarm_registry().unwrap();
    /// register_alarm(&registry, "HighCPU".to_string(), Some("90% usage".to_string()));
    /// ```
    pub fn register_alarm(
        registry: &SharedRexAlarmRegistry,
        alarm_type: String,
        alarm_details: Option<String>,
    ) {
        let alarm = super::build_rex_alarm(alarm_type, alarm_details);
        add_alarm_to_rex_registry(registry, alarm);
    }

    /// Takes and clears all alarms from the concurrent `RexAlarmRegistry`
    pub fn take_alarms_from_registry(registry: &SharedRexAlarmRegistry) -> Option<Vec<RexAlarm>> {
        match registry.lock() {
            Ok(mut guard) => guard.take_alarms(),
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.take_alarms()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::alarms::{RexAlarmBuilder, RexAlarmRegistryBuilder, build_rex_alarm};
    use strum_macros::Display;

    #[derive(Debug, Display)]
    enum TestAlarmType {
        HighCpu,
        LowMemory,
    }

    /// Given: A Rex alarm registry
    /// When: Alarms are added to the registry
    /// Then: The alarms should be retrievable with correct values
    #[test]
    fn test_rex_alarm_registry() {
        let mut rex_alarm_registry = RexAlarmRegistryBuilder::default().build().unwrap();

        let alarm = build_rex_alarm(
            TestAlarmType::HighCpu.to_string(),
            Some("90% usage".to_string()),
        );
        rex_alarm_registry.add_alarm(alarm);

        let alarm = build_rex_alarm(TestAlarmType::LowMemory.to_string(), None);
        rex_alarm_registry.add_alarm(alarm);

        let rex_alarms = rex_alarm_registry.get_alarms().unwrap();
        let expected_alarms = vec![
            RexAlarmBuilder::default()
                .alarm_type(TestAlarmType::HighCpu.to_string())
                .alarm_details(Some("90% usage".to_string()))
                .build()
                .unwrap(),
            RexAlarmBuilder::default()
                .alarm_type(TestAlarmType::LowMemory.to_string())
                .build()
                .unwrap(),
        ];

        assert_eq!(rex_alarms, &expected_alarms);
    }

    /// Given: A Rex alarm registry with alarms
    /// When: take_alarms is called on the registry
    /// Then: The alarms should be returned and clears the registry
    #[test]
    fn test_rex_alarm_registry_take_alarms() {
        let mut rex_alarm_registry = RexAlarmRegistryBuilder::default().build().unwrap();

        let alarm1 = build_rex_alarm(
            TestAlarmType::HighCpu.to_string(),
            Some("90% usage".to_string()),
        );
        let alarm2 = build_rex_alarm(TestAlarmType::LowMemory.to_string(), None);

        rex_alarm_registry.add_alarm(alarm1.clone());
        rex_alarm_registry.add_alarm(alarm2.clone());

        let taken_alarms = rex_alarm_registry.take_alarms().unwrap();
        assert_eq!(taken_alarms.len(), 2);
        assert_eq!(taken_alarms[0], alarm1);
        assert_eq!(taken_alarms[1], alarm2);

        assert!(rex_alarm_registry.get_alarms().is_none());
    }

    #[cfg(feature = "shared-registry")]
    mod shared_registry_tests {
        use crate::alarms::shared::{
            create_rex_alarm_registry, get_alarms_from_rex_registry, register_alarm,
            take_alarms_from_registry,
        };
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::sync::Arc;
        use std::thread;

        /// Given: A concurrent Rex Alarm registry
        /// When: Multiple threads add alarms to the registry concurrently
        /// Then: All alarms should be added correctly without race conditions
        #[test]
        fn test_shared_rex_alarm_registry_concurrent_access() {
            let rex_alarm_registry = create_rex_alarm_registry().unwrap();
            let worker_threads: Vec<_> = (0..4)
                .map(|thread| {
                    let registry = Arc::clone(&rex_alarm_registry);
                    thread::spawn(move || {
                        (0..5).for_each(|i| {
                            register_alarm(&registry, format!("T{thread}_A{i}"), None);
                        });
                    })
                })
                .collect();

            worker_threads.into_iter().for_each(|thread| {
                thread.join().unwrap();
            });

            let alarms = get_alarms_from_rex_registry(&rex_alarm_registry).unwrap();
            assert_eq!(alarms.len(), 20);
        }

        /// Given: A concurrent Rex Alarm registry where a thread panics while holding the lock
        /// When: Another thread tries to add an alarm after the panic
        /// Then: The alarm should still be added successfully due to mutex poisoning recovery
        #[test]
        fn test_shared_rex_alarm_registry_mutex_poisoning_recovery() {
            let rex_alarm_registry = create_rex_alarm_registry().unwrap();
            register_alarm(&rex_alarm_registry, "INITIAL_ALARM".to_string(), None);

            let registry = Arc::clone(&rex_alarm_registry);
            let panic_thread = thread::spawn(move || {
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    let lock_result = registry.lock();
                    assert!(lock_result.is_ok(), "Failed to acquire lock");
                    panic!("Intentional panic to poison the mutex");
                }));
            });
            panic_thread
                .join()
                .expect("Panic thread failed unexpectedly");
            assert!(
                rex_alarm_registry.lock().is_err(),
                "Mutex should be poisoned"
            );

            register_alarm(&rex_alarm_registry, "ALARM_AFTER_PANIC".to_string(), None);
            let alarms = take_alarms_from_registry(&rex_alarm_registry).unwrap();
            assert_eq!(alarms.len(), 2);
            assert_eq!(alarms[0].alarm_type, "INITIAL_ALARM");
            assert_eq!(alarms[1].alarm_type, "ALARM_AFTER_PANIC");

            let alarms = get_alarms_from_rex_registry(&rex_alarm_registry);
            assert!(alarms.is_none());
        }

        /// Given: A concurrent Rex Alarm registry
        /// When: Take alarms from the concurrent Rex Alarm registry is called
        /// Then: Returns and clears alarms from the concurrent Rex Alarm registry
        #[test]
        fn test_take_alarms_from_registry() {
            let rex_alarm_registry = create_rex_alarm_registry().unwrap();

            register_alarm(&rex_alarm_registry, "TEST_ALARM".to_string(), None);
            let alarms = take_alarms_from_registry(&rex_alarm_registry).unwrap();
            assert_eq!(alarms.len(), 1);
            assert_eq!(alarms[0].alarm_type, "TEST_ALARM");

            let alarms = get_alarms_from_rex_registry(&rex_alarm_registry);
            assert!(alarms.is_none());
        }
    }
}
