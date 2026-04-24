use crate::{
    register_derive_builder, register_derive_builder_key_value_setter,
    register_derive_builder_setter, register_type_with_name,
};
use rex_metrics_and_alarms::{
    common::MetricUnitType,
    metrics::{
        RexMetric, RexMetricBuilder, RexMetricDimensionsBuilder, RexMetricRegistry,
        RexMetricRegistryBuilder,
    },
};
use rhai::Engine;
use rhai::Module;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use strum::IntoEnumIterator;

pub fn register_metric_unit_types(engine: &mut Engine) {
    let mut module = Module::new();
    MetricUnitType::iter().for_each(|unit_type| {
        let unit_name = format!("{unit_type:?}");
        module.set_var(&unit_name, unit_type);
    });
    engine.register_static_module("MetricUnitType", module.into());
}

/// Collects script metrics emitted by Rhai script
#[derive(Debug, Default)]
pub struct ScriptMetricCollector {
    metric_registry: Rc<RefCell<RexMetricRegistry>>,
}

impl ScriptMetricCollector {
    /// Creates a new `ScriptMetricCollector` instance
    ///
    /// # Panics
    /// Panics if `RexMetricRegistry` builder fails to build the registry
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        Self {
            metric_registry: Rc::new(RefCell::new(
                RexMetricRegistryBuilder::default()
                    .build()
                    .expect("Failed to build metric registry"),
            )),
        }
    }

    /// Registers Script Metrics types and functions with the Rhai engine
    pub fn register_script_metric_functions(&self, engine: &mut Engine) {
        let metric_registry = Rc::clone(&self.metric_registry);
        register_derive_builder!(
            engine,
            (RexMetricBuilder, "MetricBuilder"),
            (RexMetric, "Metric"),
            setters: [
                ("name", String, metric_name),
                ("value", f64, metric_value),
                ("unit", MetricUnitType, metric_unit),
                ("dimensions", HashMap<String, String>, metric_dimension)
            ],
            option_setters: [],
            registry: metric_registry,
            add_fn: add_metric
        );

        register_metric_unit_types(engine);

        register_derive_builder!(
            engine,
            (RexMetricDimensionsBuilder, "MetricDimensionsBuilder"),
            (HashMap<String, String>, "MetricDimensions"),
            key_value_setters: [("add", add)]
        );
    }

    #[allow(clippy::map_clone)]
    pub fn get_metrics(&self) -> Option<Vec<RexMetric>> {
        self.metric_registry
            .borrow()
            .get_metrics()
            .map(|metrics| metrics.clone())
    }

    pub fn get_metric_registry(&self) -> Rc<RefCell<RexMetricRegistry>> {
        Rc::clone(&self.metric_registry)
    }
}

#[cfg(test)]
mod tests {
    use crate::ScriptMetricCollector;
    use rhai::Engine;

    /// Given: A new ScriptMetricCollector and a Rhai engine
    /// When: A script that creates and adds metrics using the builder pattern is executed
    /// Then: The metrics are correctly collected and their properties match the expected values
    #[test]
    fn test_metric_collector() {
        let engine = &mut Engine::new();
        let script_metric_collector = ScriptMetricCollector::default();
        script_metric_collector.register_script_metric_functions(engine);

        let script = r#"
            let metric_dimensions = MetricDimensionsBuilder()
                .add("MetricInfo", "Count")
                .build();

            MetricBuilder()
                .name("TestMetric1")
                .value(42.5)
                .unit(MetricUnitType::COUNT)
                .dimensions(metric_dimensions)
                .publish();

            MetricBuilder()
                .name("TestMetric2")
                .value(100.0)
                .unit(MetricUnitType::TIME)
                .publish();
        "#;

        engine.eval::<()>(script).unwrap();

        let metrics = script_metric_collector.get_metrics().unwrap();
        assert_eq!(metrics.len(), 2);
        assert!(metrics.iter().any(|m| m.metric_name == "TestMetric1"));
        assert!(metrics.iter().any(|m| m.metric_name == "TestMetric2"));
    }
}
