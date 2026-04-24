//! User identity resolution for Cedar authorization principals.

/// System implementation for retrieving username using system calls
#[derive(Debug, Copy, Clone)]
pub struct Username;

impl Username {
    /// Returns the current system username
    pub fn get_username() -> String {
        whoami::username()
    }
}

#[cfg(test)]
mod tests {
    use crate::users::Username;

    /// Given: A Username instance
    /// When: get_username is called
    /// Then: Returns a non-empty username for the current user that matches the system's actual username
    #[test]
    fn test_system_username() {
        let current_username = Username::get_username();
        let expected_username = whoami::username();

        assert!(!current_username.is_empty());
        assert_eq!(current_username, expected_username);
    }
}
