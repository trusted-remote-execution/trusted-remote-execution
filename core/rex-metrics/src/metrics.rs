use crate::common::MetricUnitType;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use derive_builder::Builder;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// Builder for creating Rex metric dimension
///
/// # Examples
///
/// ```
/// use rex_metrics_and_alarms::metrics::RexMetricDimensionsBuilder;
///
/// let dimensions = RexMetricDimensionsBuilder::default()
///     .add("service", "rex")
///     .add("component", "agent")
///     .build();
///
/// assert_eq!(dimensions.get("service").unwrap(), "rex");
/// assert_eq!(dimensions.get("component").unwrap(), "agent");
/// ```
#[derive(Debug, Clone, Default)]
pub struct RexMetricDimensionsBuilder {
    metric_dimensions: HashMap<String, String>,
}

impl RexMetricDimensionsBuilder {
    /// Adds a dimension with the specified key and value.
    #[must_use]
    pub fn add<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.metric_dimensions.insert(key.into(), value.into());
        self
    }

    /// Builds and returns the dimensions
    pub fn build(self) -> HashMap<String, String> {
        self.metric_dimensions
    }
}

/// Represents a metric in the REX components.
///
/// # Fields
/// * `metric_name` - The name identifier for the metric
/// * `metric_value` - The value of the metric
/// * `metric_unit` - The unit of measurement for the metric
/// * `metric_dimension` - key-value pairs providing additional context about the metric (max 30 pairs)
/// * `metric_timestamp` - The timestamp when the metric was recorded
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use rex_metrics_and_alarms::metrics::{RexMetricBuilder};
/// use rex_metrics_and_alarms::common::MetricUnitType;
///
/// // Create a metric with builder pattern
/// let mut dimensions = HashMap::new();
/// dimensions.insert("service".to_string(), "rex".to_string());
/// dimensions.insert("component".to_string(), "agent".to_string());
///
/// let metric = RexMetricBuilder::default()
///     .metric_name("api_latency".to_string())
///     .metric_value(42.5)
///     .metric_unit(MetricUnitType::TIME)
///     .metric_dimension(dimensions)
///     .build()
///     .unwrap();
///
/// assert_eq!(metric.metric_name, "api_latency");
/// assert_eq!(metric.metric_value, 42.5);
/// assert_eq!(metric.metric_unit, MetricUnitType::TIME);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Builder)]
#[builder(setter(into))]
#[allow(clippy::implicit_hasher)]
pub struct RexMetric {
    pub metric_name: String,
    pub metric_value: f64,
    pub metric_unit: MetricUnitType,
    #[builder(default)]
    pub metric_dimension: HashMap<String, String>,
    #[builder(default = "Utc::now()")]
    pub metric_timestamp: DateTime<Utc>,
}

/// Registry which collects `RexMetric` instances for centralized management.
///
/// # Examples
///
/// ```
/// use rex_metrics_and_alarms::metrics::{RexMetricRegistryBuilder, build_rex_metric};
/// use rex_metrics_and_alarms::common::MetricUnitType;
/// use std::collections::HashMap;
///
/// // Create a new registry
/// let registry = RexMetricRegistryBuilder::default().build().unwrap();
///
/// // Add a metric to the registry
/// let metric = build_rex_metric(
///     "cpu_usage".to_string(),
///     75.5,
///     MetricUnitType::COUNT,
///     HashMap::new(),
/// );
/// registry.add_metric(metric);
///
/// // Retrieve metrics from the registry
/// let metrics = registry.get_metrics().unwrap();
/// assert_eq!(metrics.len(), 1);
///
/// // Get a specific metric by name
/// let cpu_metric = registry.get_metric("cpu_usage").unwrap();
/// assert_eq!(cpu_metric.metric_value, 75.5);
///
/// // Take all metrics (this also clears the registry)
/// let all_metrics = registry.take_metrics().unwrap();
/// assert!(registry.get_metrics().is_none()); // Registry is now empty
/// ```
#[derive(Builder, Debug, Default, Clone)]
#[builder(derive(Debug))]
pub struct RexMetricRegistry {
    #[builder(default)]
    metrics: DashMap<String, RexMetric>,
}

impl RexMetricRegistry {
    pub fn add_metric(&self, rex_metric: RexMetric) {
        self.metrics
            .insert(rex_metric.metric_name.clone(), rex_metric);
    }

    pub fn get_metrics(&self) -> Option<Vec<RexMetric>> {
        (!self.metrics.is_empty())
            .then_some(self.metrics.iter().map(|m| m.value().clone()).collect())
    }

    pub fn get_metric(&self, name: &str) -> Option<RexMetric> {
        self.metrics.get(name).map(|metric| metric.value().clone())
    }

    pub fn take_metrics(&self) -> Option<Vec<RexMetric>> {
        (!self.metrics.is_empty()).then(|| {
            let metrics = self.metrics.iter().map(|m| m.value().clone()).collect();
            self.metrics.clear();
            metrics
        })
    }
}

/// Creates a new metric with the current UTC time as the timestamp.
///
/// # Note
/// * Arguments in this method can change during future changes.
///   To avoid breaking changes, use `add_metric` directly.
/// # Panics
/// * This method will never panic since we explicitly provide all required fields for `RexMetric`
///
/// # Examples
///
/// ```
/// use rex_metrics_and_alarms::metrics::build_rex_metric;
/// use rex_metrics_and_alarms::common::MetricUnitType;
/// use std::collections::HashMap;
///
/// // Create a simple metric with no dimensions
/// let simple_metric = build_rex_metric(
///     "request_count".to_string(),
///     100.0,
///     MetricUnitType::COUNT,
///     HashMap::new(),
/// );
///
/// // Create a metric with dimensions
/// let mut dimensions = HashMap::new();
/// dimensions.insert("region".to_string(), "us-west-2".to_string());
/// dimensions.insert("instance_type".to_string(), "t3.micro".to_string());
///
/// let detailed_metric = build_rex_metric(
///     "memory_usage".to_string(),
///     85.2,
///     MetricUnitType::COUNT,
///     dimensions,
/// );
/// ```
#[allow(clippy::unwrap_used)]
#[allow(clippy::implicit_hasher)]
pub fn build_rex_metric(
    metric_name: String,
    metric_value: f64,
    metric_unit: MetricUnitType,
    metric_dimension: HashMap<String, String>,
) -> RexMetric {
    RexMetricBuilder::default()
        .metric_name(metric_name)
        .metric_value(metric_value)
        .metric_unit(metric_unit)
        .metric_dimension(metric_dimension)
        .build()
        .unwrap()
}

/// Creates a new failure count metric using [`build_rex_metric`] with dimensions.
///
/// # Examples
///
/// ```
/// use rex_metrics_and_alarms::metrics::{build_rex_failure_count_metric, RexMetricRegistry, RexMetricRegistryBuilder};
///
/// // Create a failure count metric
/// let failure_metric = build_rex_failure_count_metric("api_call_failures".to_string());
///
/// // Verify the metric properties
/// assert_eq!(failure_metric.metric_name, "api_call_failures");
/// assert_eq!(failure_metric.metric_value, 1.0);
/// assert_eq!(failure_metric.metric_dimension.get("MetricInfo").unwrap(), "FailureCount");
///
/// // Add to a registry
/// let registry = RexMetricRegistryBuilder::default().build().unwrap();
/// registry.add_metric(failure_metric);
/// ```
pub fn build_rex_failure_count_metric(metric_name: String) -> RexMetric {
    let mut dimension = HashMap::new();
    dimension.insert("MetricInfo".to_string(), "FailureCount".to_string());
    build_rex_metric(metric_name, 1.0, MetricUnitType::COUNT, dimension)
}

/// Creates a new success count metric using [`build_rex_metric`] with dimensions.
///
/// # Examples
///
/// ```
/// use rex_metrics_and_alarms::metrics::{build_rex_success_count_metric, RexMetricRegistry, RexMetricRegistryBuilder};
///
/// // Create a success count metric
/// let success_metric = build_rex_success_count_metric("api_call_successes".to_string());
///
/// // Verify the metric properties
/// assert_eq!(success_metric.metric_name, "api_call_successes");
/// assert_eq!(success_metric.metric_value, 1.0);
/// assert_eq!(success_metric.metric_dimension.get("MetricInfo").unwrap(), "SuccessCount");
///
/// // Add to a registry
/// let registry = RexMetricRegistryBuilder::default().build().unwrap();
/// registry.add_metric(success_metric);
/// ```
pub fn build_rex_success_count_metric(metric_name: String) -> RexMetric {
    let mut dimension = HashMap::new();
    dimension.insert("MetricInfo".to_string(), "SuccessCount".to_string());
    build_rex_metric(metric_name, 1.0, MetricUnitType::COUNT, dimension)
}

/// Creates a new time metric using [`build_rex_metric`] with dimensions.
///
/// # Examples
///
/// ```
/// use rex_metrics_and_alarms::metrics::{build_rex_duration_metric, RexMetricRegistry, RexMetricRegistryBuilder};
///
/// // Create a time duration metric
/// let duration_metric = build_rex_duration_metric("api_latency".to_string(), 42.5);
///
/// // Verify the metric properties
/// assert_eq!(duration_metric.metric_name, "api_latency");
/// assert_eq!(duration_metric.metric_value, 42.5);
/// assert_eq!(duration_metric.metric_dimension.get("MetricInfo").unwrap(), "Duration");
///
/// // Add to a registry
/// let registry = RexMetricRegistryBuilder::default().build().unwrap();
/// registry.add_metric(duration_metric);
/// ```
pub fn build_rex_duration_metric(metric_name: String, metric_value: f64) -> RexMetric {
    let mut dimension = HashMap::new();
    dimension.insert("MetricInfo".to_string(), "Duration".to_string());
    build_rex_metric(metric_name, metric_value, MetricUnitType::TIME, dimension)
}

/// Shared registry module providing thread-safe metric registry functionality.
/// This module is only available when the `shared-registry` feature is enabled.
#[cfg(feature = "shared-registry")]
pub mod shared {
    use super::{MetricUnitType, RexMetric, RexMetricRegistry, build_rex_metric};
    use anyhow::Error;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Concurrent version of the `RexMetricRegistry` that can be safely shared across threads.
    /// Uses `Arc` for thread-safe reference counting since `RexMetricRegistry` internally uses `DashMap`.
    pub type SharedRexMetricRegistry = Arc<RexMetricRegistry>;

    /// Creates a new concurrent `RexMetricRegistry` that can be safely shared across threads.
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_metrics_and_alarms::metrics::shared;
    ///
    /// let registry = shared::create_rex_metric_registry().unwrap();
    /// ```
    pub fn create_rex_metric_registry() -> Result<SharedRexMetricRegistry, Error> {
        Ok(Arc::new(RexMetricRegistry::default()))
    }

    /// Adds a metric to a shared registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_metrics_and_alarms::metrics::{shared, build_rex_metric};
    /// use rex_metrics_and_alarms::common::MetricUnitType;
    /// use std::collections::HashMap;
    ///
    /// let registry = shared::create_rex_metric_registry().unwrap();
    /// let metric = build_rex_metric(
    ///     "cpu_usage".to_string(),
    ///     75.5,
    ///     MetricUnitType::COUNT,
    ///     HashMap::new(),
    /// );
    /// shared::add_metric_to_rex_registry(&registry, metric);
    /// ```
    pub fn add_metric_to_rex_registry(registry: &SharedRexMetricRegistry, metric: RexMetric) {
        registry.add_metric(metric);
    }

    /// Retrieves all metrics from a shared registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_metrics_and_alarms::metrics::{shared, build_rex_metric};
    /// use rex_metrics_and_alarms::common::MetricUnitType;
    /// use std::collections::HashMap;
    ///
    /// let registry = shared::create_rex_metric_registry().unwrap();
    /// let metric = build_rex_metric(
    ///     "cpu_usage".to_string(),
    ///     75.5,
    ///     MetricUnitType::COUNT,
    ///     HashMap::new(),
    /// );
    /// shared::add_metric_to_rex_registry(&registry, metric);
    ///
    /// let metrics = shared::get_metrics_from_rex_registry(&registry).unwrap();
    /// assert_eq!(metrics.len(), 1);
    /// ```
    pub fn get_metrics_from_rex_registry(
        registry: &SharedRexMetricRegistry,
    ) -> Option<Vec<RexMetric>> {
        registry.get_metrics()
    }

    /// Retrieves a specific metric by name from a shared registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_metrics_and_alarms::metrics::{shared, build_rex_metric};
    /// use rex_metrics_and_alarms::common::MetricUnitType;
    /// use std::collections::HashMap;
    ///
    /// // Create a shared registry and add a metric
    /// let registry = shared::create_rex_metric_registry().unwrap();
    /// let metric = build_rex_metric(
    ///     "cpu_usage".to_string(),
    ///     75.5,
    ///     MetricUnitType::COUNT,
    ///     HashMap::new(),
    /// );
    /// shared::add_metric_to_rex_registry(&registry, metric);
    ///
    /// // Get the specific metric by name
    /// let cpu_metric = shared::get_metric_from_rex_registry(&registry, "cpu_usage").unwrap();
    /// assert_eq!(cpu_metric.metric_value, 75.5);
    ///
    /// // Attempt to get a non-existent metric
    /// let nonexistent = shared::get_metric_from_rex_registry(&registry, "nonexistent");
    /// assert!(nonexistent.is_none());
    /// ```
    pub fn get_metric_from_rex_registry(
        registry: &SharedRexMetricRegistry,
        name: &str,
    ) -> Option<RexMetric> {
        registry.get_metric(name)
    }

    /// Retrieves all metrics from a shared registry and clears the registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_metrics_and_alarms::metrics::{shared, build_rex_metric};
    /// use rex_metrics_and_alarms::common::MetricUnitType;
    /// use std::collections::HashMap;
    ///
    /// // Create a shared registry and add metrics
    /// let registry = shared::create_rex_metric_registry().unwrap();
    ///
    /// let metric1 = build_rex_metric(
    ///     "metric1".to_string(),
    ///     10.0,
    ///     MetricUnitType::COUNT,
    ///     HashMap::new(),
    /// );
    /// let metric2 = build_rex_metric(
    ///     "metric2".to_string(),
    ///     20.0,
    ///     MetricUnitType::COUNT,
    ///     HashMap::new(),
    /// );
    ///
    /// shared::add_metric_to_rex_registry(&registry, metric1);
    /// shared::add_metric_to_rex_registry(&registry, metric2);
    ///
    /// // Take all metrics (this also clears the registry)
    /// let metrics = shared::take_metrics_from_registry(&registry).unwrap();
    /// assert_eq!(metrics.len(), 2);
    ///
    /// // Registry should now be empty
    /// assert!(shared::get_metrics_from_rex_registry(&registry).is_none());
    /// ```
    pub fn take_metrics_from_registry(
        registry: &SharedRexMetricRegistry,
    ) -> Option<Vec<RexMetric>> {
        registry.take_metrics()
    }

    /// Convenience function to create a metric and add it to a shared registry in one step.
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_metrics_and_alarms::metrics::shared;
    /// use rex_metrics_and_alarms::common::MetricUnitType;
    /// use std::collections::HashMap;
    ///
    /// // Create a shared registry
    /// let registry = shared::create_rex_metric_registry().unwrap();
    ///
    /// // Create dimensions
    /// let mut dimensions = HashMap::new();
    /// dimensions.insert("region".to_string(), "us-west-2".to_string());
    /// dimensions.insert("service".to_string(), "rex".to_string());
    ///
    /// // Register a metric directly to the registry
    /// shared::register_metric(
    ///     &registry,
    ///     "api_latency".to_string(),
    ///     42.5,
    ///     MetricUnitType::TIME,
    ///     dimensions,
    /// );
    ///
    /// // Verify the metric was added
    /// let metric = shared::get_metric_from_rex_registry(&registry, "api_latency").unwrap();
    /// assert_eq!(metric.metric_value, 42.5);
    /// ```
    #[allow(clippy::implicit_hasher)]
    pub fn register_metric(
        registry: &SharedRexMetricRegistry,
        metric_name: String,
        metric_value: f64,
        metric_unit: MetricUnitType,
        metric_dimension: HashMap<String, String>,
    ) {
        let metric = build_rex_metric(metric_name, metric_value, metric_unit, metric_dimension);
        add_metric_to_rex_registry(registry, metric);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A RexMetricDimensionBuilder
    /// When: Adding dimensions and building
    /// Then: Should create a HashMap with the correct dimensions
    #[test]
    fn test_rex_metric_dimension_builder() {
        let dimensions = RexMetricDimensionsBuilder::default()
            .add("service", "rex")
            .add("component", "agent")
            .build();

        assert_eq!(dimensions.len(), 2);
        assert_eq!(dimensions.get("service").unwrap(), "rex");
        assert_eq!(dimensions.get("component").unwrap(), "agent");
    }

    /// Given: A RexMetricBuilder
    /// When: Building with all required fields
    /// Then: Should create a valid RexMetric
    #[test]
    fn test_rex_metric_creation() {
        let mut dimensions = HashMap::new();
        dimensions.insert("key1".to_string(), "value1".to_string());

        let metric = RexMetricBuilder::default()
            .metric_name("TEST".to_string())
            .metric_value(42.0)
            .metric_unit(MetricUnitType::COUNT)
            .metric_dimension(dimensions.clone())
            .build()
            .unwrap();

        assert_eq!(metric.metric_name, "TEST");
        assert_eq!(metric.metric_value, 42.0);
        assert_eq!(metric.metric_unit, MetricUnitType::COUNT);
        assert_eq!(metric.metric_dimension, dimensions);
    }

    /// Given: A RexMetricBuilder
    /// When: Building with only required fields
    /// Then: Should create a valid RexMetric with default values for optional fields
    #[test]
    fn test_rex_metric_defaults() {
        let before = Utc::now();
        let metric = RexMetricBuilder::default()
            .metric_name("TEST".to_string())
            .metric_value(1.0)
            .metric_unit(MetricUnitType::COUNT)
            .build()
            .unwrap();
        let after = Utc::now();

        assert!(metric.metric_dimension.is_empty());
        assert!(metric.metric_timestamp >= before && metric.metric_timestamp <= after);
    }

    /// Given: An empty RexMetricRegistry
    /// When: Adding a metric and retrieving all metrics
    /// Then: Should store and return the metric correctly
    #[test]
    fn test_registry_basic_operations() {
        let registry = RexMetricRegistryBuilder::default().build().unwrap();
        assert!(registry.get_metrics().is_none());

        let metric = build_rex_metric(
            "TEST".to_string(),
            1.0,
            MetricUnitType::COUNT,
            HashMap::new(),
        );
        registry.add_metric(metric.clone());

        let metrics = registry.get_metrics().unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0], metric);
    }

    /// Given: A RexMetricRegistry with one metric
    /// When: Getting a specific metric by name
    /// Then: Should return the correct metric or None for non-existent metrics
    #[test]
    fn test_get_specific_metric() {
        let registry = RexMetricRegistryBuilder::default().build().unwrap();

        let metric = build_rex_metric(
            "TEST".to_string(),
            1.0,
            MetricUnitType::COUNT,
            HashMap::new(),
        );
        registry.add_metric(metric.clone());

        let retrieved = registry.get_metric("TEST").unwrap();
        assert_eq!(retrieved, metric);
        assert!(registry.get_metric("NONEXISTENT").is_none());
    }

    /// Given: A RexMetricRegistry with one metric
    /// When: Taking all metrics from the registry
    /// Then: Should return all metrics and clear the registry
    #[test]
    fn test_take_metrics() {
        let registry = RexMetricRegistryBuilder::default().build().unwrap();
        assert!(registry.take_metrics().is_none());

        let metric = build_rex_metric(
            "TEST".to_string(),
            1.0,
            MetricUnitType::COUNT,
            HashMap::new(),
        );
        registry.add_metric(metric.clone());

        let taken = registry.take_metrics().unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0], metric);
        assert!(registry.get_metrics().is_none());
    }

    /// Given: A RexMetricRegistry
    /// When: Updating an existing metric with new values including a failure count
    /// Then: Should override the previous value and set correct dimensions
    #[test]
    fn test_metric_update() {
        let registry = RexMetricRegistryBuilder::default().build().unwrap();

        let metric1 = build_rex_metric(
            "UPDATE_TEST".to_string(),
            3.0,
            MetricUnitType::COUNT,
            HashMap::new(),
        );

        let metric2 = build_rex_metric(
            "UPDATE_TEST".to_string(),
            2.0,
            MetricUnitType::COUNT,
            HashMap::new(),
        );

        let metric3 = build_rex_failure_count_metric("UPDATE_TEST".to_string());

        registry.add_metric(metric1);
        registry.add_metric(metric2);
        registry.add_metric(metric3);

        let retrieved = registry.get_metric("UPDATE_TEST").unwrap();
        assert_eq!(retrieved.metric_value, 1.0);

        // Additionally verify the dimension is set correctly for failure count
        assert_eq!(
            retrieved.metric_dimension.get("MetricInfo"),
            Some(&"FailureCount".to_string())
        );
    }

    /// Given: A success count metric
    /// When: The build_rex_success_count_metric is invoked
    /// Then: Should create a RexMetric with the correct properties and dimension
    #[test]
    fn test_build_rex_success_count_metric() {
        let rex_metric_name = "TEST_SUCCESS".to_string();
        let rex_metric = build_rex_success_count_metric(rex_metric_name);

        assert_eq!(rex_metric.metric_name, "TEST_SUCCESS");
        assert_eq!(rex_metric.metric_value, 1.0);
        assert_eq!(rex_metric.metric_unit, MetricUnitType::COUNT);
        assert_eq!(
            rex_metric.metric_dimension.get("MetricInfo"),
            Some(&"SuccessCount".to_string())
        );
    }

    /// Given: A time metric with a specific duration
    /// When: The build_rex_duration_metric is invoked
    /// Then: Should create a RexMetric with the correct properties and dimension
    #[test]
    fn test_build_rex_duration_metric() {
        let rex_metric_name = "TEST_TIME".to_string();
        let rex_metric_value = 121.0;
        let rex_metric = build_rex_duration_metric(rex_metric_name, rex_metric_value);

        assert_eq!(rex_metric.metric_name, "TEST_TIME");
        assert_eq!(rex_metric.metric_value, rex_metric_value);
        assert_eq!(rex_metric.metric_unit, MetricUnitType::TIME);
        assert_eq!(
            rex_metric.metric_dimension.get("MetricInfo"),
            Some(&"Duration".to_string())
        );
    }

    /// Given: A RexMetricBuilder
    /// When: Creating a metric with the maximum number of dimensions (30)
    /// Then: Should handle the large dimension map correctly
    #[test]
    fn test_max_dimensions() {
        let mut dimensions = HashMap::new();
        for i in 0..30 {
            dimensions.insert(format!("key{}", i), format!("value{}", i));
        }

        let metric = build_rex_metric(
            "MAX_DIM_TEST".to_string(),
            1.0,
            MetricUnitType::COUNT,
            dimensions.clone(),
        );

        assert_eq!(metric.metric_dimension.len(), 30);
    }

    #[cfg(feature = "shared-registry")]
    mod shared_registry_tests {
        use super::*;
        use crate::metrics::shared;
        use std::sync::Arc;
        use std::thread;

        /// Given: A SharedRexMetricRegistry
        /// When: Multiple threads concurrently add and retrieve metrics
        /// Then: Should handle concurrent operations correctly
        #[test]
        fn test_shared_registry() {
            let registry = shared::create_rex_metric_registry().unwrap();
            let add_registry = Arc::clone(&registry);
            let get_registry = Arc::clone(&registry);

            let handle = thread::spawn(move || {
                for i in 0..10 {
                    shared::register_metric(
                        &add_registry,
                        format!("METRIC_{}", i),
                        i as f64,
                        MetricUnitType::COUNT,
                        HashMap::new(),
                    );
                }
            });

            let get_handle = thread::spawn(move || {
                thread::sleep(std::time::Duration::from_millis(50));
                shared::get_metrics_from_rex_registry(&get_registry)
            });

            handle.join().unwrap();
            let metrics = get_handle.join().unwrap().unwrap();
            assert_eq!(metrics.len(), 10);
        }

        /// Given: A SharedRexMetricRegistry
        /// When: Performing various shared operations (add, get, take)
        /// Then: Should maintain consistency across operations
        #[test]
        fn test_shared_registry_operations() {
            let registry = shared::create_rex_metric_registry().unwrap();

            let metric = build_rex_metric(
                "SHARED_TEST".to_string(),
                1.0,
                MetricUnitType::COUNT,
                HashMap::new(),
            );

            shared::add_metric_to_rex_registry(&registry, metric.clone());

            let retrieved = shared::get_metric_from_rex_registry(&registry, "SHARED_TEST").unwrap();
            assert_eq!(retrieved, metric);

            let taken = shared::take_metrics_from_registry(&registry).unwrap();
            assert_eq!(taken.len(), 1);
            assert!(shared::get_metrics_from_rex_registry(&registry).is_none());
        }

        /// Given: A SharedRexMetricRegistry
        /// When: Multiple threads concurrently add and take metrics
        /// Then: Should handle all operations correctly without data loss
        #[test]
        fn test_concurrent_add_and_take() {
            let registry = shared::create_rex_metric_registry().unwrap();
            let add_registry = Arc::clone(&registry);
            let take_registry = Arc::clone(&registry);

            // Thread that adds metrics
            let add_handle = thread::spawn(move || {
                for i in 0..100 {
                    shared::register_metric(
                        &add_registry,
                        format!("CONCURRENT_METRIC_{}", i),
                        i as f64,
                        MetricUnitType::COUNT,
                        HashMap::new(),
                    );
                    // Small sleep to increase chance of interleaving with take operations
                    if i % 10 == 0 {
                        thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            });

            // Thread that takes metrics periodically
            let take_handle = thread::spawn(move || {
                let mut total_taken = 0;
                for _ in 0..10 {
                    thread::sleep(std::time::Duration::from_millis(5));
                    if let Some(metrics) = shared::take_metrics_from_registry(&take_registry) {
                        total_taken += metrics.len();
                    }
                }
                total_taken
            });

            add_handle.join().unwrap();
            let total_taken = take_handle.join().unwrap();

            // Either all metrics were taken or none are left
            let remaining = shared::get_metrics_from_rex_registry(&registry);
            let remaining_count = remaining.map_or(0, |m| m.len());

            assert_eq!(
                total_taken + remaining_count,
                100,
                "Expected all 100 metrics to be accounted for"
            );
        }
    }
}
