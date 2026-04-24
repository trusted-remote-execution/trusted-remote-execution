use crate::{
    register_derive_builder, register_derive_builder_option_setter, register_derive_builder_setter,
    register_type_with_name,
};
use rex_metrics_and_alarms::alarms::{
    RexAlarm, RexAlarmBuilder, RexAlarmRegistry, RexAlarmRegistryBuilder,
};
use rhai::Engine;
use std::cell::RefCell;
use std::rc::Rc;

/// Collects script alarms emitted by Rhai script
#[derive(Debug, Default)]
pub struct ScriptAlarmCollector {
    alarm_registry: Rc<RefCell<RexAlarmRegistry>>,
}

impl ScriptAlarmCollector {
    /// Creates a new `ScriptAlarmCollector` instance
    ///
    /// # Panics
    /// Panics if `RexAlarmRegistry` builder fails to build the registry
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        Self {
            alarm_registry: Rc::new(RefCell::new(
                RexAlarmRegistryBuilder::default()
                    .build()
                    .expect("Failed to build alarm registry"),
            )),
        }
    }

    /// Registers Script Alarms types and functions with the Rhai engine
    pub fn register_script_alarm_functions(&self, engine: &mut Engine) {
        let alarm_registry = Rc::clone(&self.alarm_registry);
        register_derive_builder!(
            engine,
            (RexAlarmBuilder, "AlarmBuilder"),
            (RexAlarm, "Alarm"),
            setters: [
                ("type", String, alarm_type)
            ],
            option_setters: [
                ("details", String, alarm_details)
            ],
            registry: alarm_registry,
            add_fn: add_alarm
        );
    }

    pub fn get_alarms(&self) -> Option<Vec<RexAlarm>> {
        self.alarm_registry.borrow().get_alarms().cloned()
    }

    pub fn get_alarm_registry(&self) -> Rc<RefCell<RexAlarmRegistry>> {
        Rc::clone(&self.alarm_registry)
    }
}

#[cfg(test)]
mod tests {
    use crate::ScriptAlarmCollector;
    use rhai::Engine;

    /// Given: A new ScriptAlarmCollector and a Rhai engine
    /// When: A script that creates and adds an alarm using the builder pattern is executed
    /// Then: The alarm is correctly collected and its properties match the expected values
    #[test]
    fn test_alarm_collector() {
        let engine = &mut Engine::new();
        let script_alarm_collector = ScriptAlarmCollector::default();
        script_alarm_collector.register_script_alarm_functions(engine);

        let script = r#"
            AlarmBuilder()
                .type("TestScriptAlarm1")
                .details("Test alarm details 1")
                .publish();

            AlarmBuilder()
                .type("TestScriptAlarm2")
                .publish();
        "#;

        engine.eval::<()>(script).unwrap();

        let alarms = script_alarm_collector.get_alarms().unwrap();
        assert_eq!(alarms.len(), 2);
        assert_eq!(alarms[0].alarm_type, "TestScriptAlarm1");
        assert_eq!(alarms[1].alarm_type, "TestScriptAlarm2");
    }
}
