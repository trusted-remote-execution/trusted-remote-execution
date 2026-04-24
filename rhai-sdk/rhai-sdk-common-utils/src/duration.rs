use rhai::Dynamic;
use rhai::plugin::{
    FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult, TypeId,
    export_module, mem,
};

/// [`std::time::Duration`] module for Rhai
#[export_module]
pub mod duration_module {
    use std::time::Duration as StdDuration;

    pub type Duration = StdDuration;

    /// Create a new Duration from a number of seconds.
    ///
    /// If a negative duration is provided, a duration of
    /// 0 seconds will be used.
    #[rhai_fn(global)]
    pub fn from_secs(secs: i64) -> Duration {
        Duration::from_secs(secs.try_into().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use rex_test_utils::rhai::common::create_test_engine_and_register;
    use rstest::rstest;
    use std::time::Duration;

    /// Given: A number of seconds
    /// When: Calling from_secs with that value in Rhai
    /// Then: A Duration with the correct seconds value should be created
    #[rstest]
    #[case(0, "zero seconds")]
    #[case(1, "one second")]
    #[case(60, "one minute")]
    #[case(3600, "one hour")]
    #[case(86400, "one day")]
    fn test_from_secs(#[case] secs: u64, #[case] description: &str) {
        let engine = create_test_engine_and_register();
        let script = format!("from_secs({})", secs);
        let result = engine.eval::<Duration>(&script).unwrap();
        assert_eq!(
            result,
            Duration::from_secs(secs),
            "Failed for: {}",
            description
        );
    }
}
