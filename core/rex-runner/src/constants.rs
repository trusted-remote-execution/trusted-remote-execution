use strum_macros::Display;

pub const REX_CONFIG_SCOPE: &str = "rex_config";

#[derive(Display, Debug, Copy, Clone)]
#[allow(clippy::enum_variant_names)]
#[non_exhaustive]
pub enum RexRunnerAlarm {
    RexRunnerScriptExecutionFailure,
    RexRunnerScriptCompilationFailure,
    RexRunnerPrivilegeEscalation,
    RexRunnerStdinReadFailure,
    RexRunnerScriptArgumentValidationFailure,
    RexRunnerInternalAlarm,
}

#[derive(Display, Debug, Copy, Clone)]
#[allow(clippy::enum_variant_names)]
#[non_exhaustive]
pub enum RexRunnerMetric {
    RexRunnerScriptExecutionFailureCount,
    RexRunnerScriptCompilationFailureCount,
    RexRunnerScriptArgumentValidationFailureCount,
    RexRunnerPrivilegeEscalationCount,
    RexRunnerStdinReadFailureCount,
    RexRunnerScriptExecutionSuccessCount,
    RexRunnerScriptExecutionTime,
    RexRunnerTotalExecutionTime,
    RexRunnerProcessCpuUsage,
    RexRunnerProcessRssMemoryUsageAverage,
    RexRunnerProcessVirtualMemoryUsageAverage,
}
