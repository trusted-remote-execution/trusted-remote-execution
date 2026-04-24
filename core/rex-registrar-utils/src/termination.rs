use std::cell::RefCell;
use std::rc::Rc;

/// A shared termination flag that can be passed between components
/// to signal when script execution should be terminated immediately.
#[derive(Debug, Clone, Default)]
pub struct TerminationFlag {
    inner: Rc<RefCell<TerminationFlagInner>>,
}

#[derive(Debug, Default)]
struct TerminationFlagInner {
    flag: bool,
    error: Option<String>,
}

impl TerminationFlag {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(TerminationFlagInner {
                flag: false,
                error: None,
            })),
        }
    }

    /// Signal that script execution should terminate immediately with an error.
    pub fn signal_termination(&self, error: String) {
        let mut inner = self.inner.borrow_mut();
        inner.flag = true;
        inner.error = Some(error);
    }

    /// Check if termination has been requested.
    /// Returns true if any component has called `signal_termination()`.
    pub fn should_terminate(&self) -> bool {
        self.inner.borrow().flag
    }

    /// Get the termination error message if one was set.
    pub fn error(&self) -> Option<String> {
        self.inner.borrow().error.clone()
    }

    /// Reset the termination flag back to false and clear the error.
    #[cfg(test)]
    pub fn reset(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.flag = false;
        inner.error = None;
    }
}

#[cfg(test)]
mod tests {
    use crate::termination::TerminationFlag;

    /// Given: A newly created TerminationFlag
    /// When: Testing initial state, signaling, reset and clone behavior
    /// Then: The flag should behave correctly in all scenarios
    #[test]
    fn test_termination_flag() {
        let flag = TerminationFlag::new();
        assert!(!flag.should_terminate(), "Flag should start as false");

        flag.signal_termination("Test error".to_string());
        assert!(
            flag.should_terminate(),
            "Flag should be true after signaling"
        );
        assert_eq!(flag.error(), Some("Test error".to_string()));

        flag.reset();
        assert!(!flag.should_terminate(), "Flag should be false after reset");
        assert_eq!(flag.error(), None);

        let clone = flag.clone();
        clone.signal_termination("Clone error".to_string());
        assert!(
            flag.should_terminate(),
            "Original should see termination signaled by clone"
        );
        assert_eq!(flag.error(), Some("Clone error".to_string()));
    }
}
