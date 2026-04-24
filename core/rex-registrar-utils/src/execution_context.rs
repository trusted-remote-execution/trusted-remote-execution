use crate::termination::TerminationFlag;
use derive_builder::Builder;

/// Context for script execution containing shared state and flags
///
/// This struct holds an execution-related state that needs to be shared
/// across different components during script execution.
///
/// # Examples
///
/// ```
/// use rex_runner_registrar_utils::execution_context::ExecutionContext;
///
/// // Create with defaults
/// let context = ExecutionContext::default();
///
/// // Access termination flag
/// if context.termination_flag().should_terminate() {
///     // Handle termination
/// }
/// ```
#[derive(Debug, Clone, Default, Builder)]
#[builder(derive(Debug))]
pub struct ExecutionContext {
    #[builder(default = "TerminationFlag::new()")]
    termination_flag: TerminationFlag,
}

impl ExecutionContext {
    /// Returns a reference to the termination flag
    ///
    /// The termination flag is used to signal when script execution
    /// should be terminated immediately due to critical errors.
    pub const fn termination_flag(&self) -> &TerminationFlag {
        &self.termination_flag
    }
}

#[cfg(test)]
mod tests {
    use crate::execution_context::ExecutionContext;

    /// Given: An ExecutionContext
    /// When: Using ExecutionContext creation for signaling termination
    /// Then: Should behave correctly for all operations
    #[test]
    fn test_execution_context_lifecycle() {
        let context = ExecutionContext::default();
        assert!(!context.termination_flag().should_terminate());

        context
            .termination_flag()
            .signal_termination("Test error".to_string());
        assert!(context.termination_flag().should_terminate());
        assert_eq!(
            context.termination_flag().error(),
            Some("Test error".to_string())
        );

        let context2 = ExecutionContext::default();
        let clone = context2.clone();
        context2
            .termination_flag()
            .signal_termination("Clone error".to_string());
        assert!(clone.termination_flag().should_terminate());
        assert_eq!(
            clone.termination_flag().error(),
            Some("Clone error".to_string())
        );
    }
}
