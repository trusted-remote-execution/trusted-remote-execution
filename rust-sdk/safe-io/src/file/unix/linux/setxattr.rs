use crate::RcFileHandle;
use crate::errors::RustSafeIoError;
use crate::is_authorized_with_context;
use crate::options::SetXAttrOptions;
use anyhow::Result;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};
use std::os::fd::AsFd;

/// Helper to validates a `SELinux` context component input (user, role, type, or level).
fn validate_selinux_component(value: &str, component_name: &str) -> Result<(), RustSafeIoError> {
    if value.trim().is_empty() {
        return Err(RustSafeIoError::InvalidArguments {
            reason: format!("SELinux {component_name} cannot be empty or whitespace-only"),
        });
    }

    if value != value.trim() {
        return Err(RustSafeIoError::InvalidArguments {
            reason: format!("SELinux {component_name} cannot have leading or trailing whitespace"),
        });
    }

    if value.contains(':') {
        return Err(RustSafeIoError::InvalidArguments {
            reason: format!(
                "SELinux {component_name} cannot contain ':' character as it is the context delimiter"
            ),
        });
    }

    if value.chars().any(char::is_control) {
        return Err(RustSafeIoError::InvalidArguments {
            reason: format!("SELinux {component_name} cannot contain control characters"),
        });
    }

    Ok(())
}

/// Helper function to get existing xattr value
fn get_old_xattr_value<Fd: AsFd>(fd: Fd, name: &str) -> Result<Vec<u8>, RustSafeIoError> {
    let mut buffer = vec![0u8; 1024];
    match fgetxattr(fd, name, &mut buffer) {
        Ok(size) => {
            buffer.truncate(size);
            Ok(buffer)
        }
        Err(e) => Err(RustSafeIoError::from(e)),
    }
}

impl RcFileHandle {
    /// Sets an extended attribute on the file.
    ///
    /// Extended attributes allow storing additional metadata with files on supported filesystems.
    /// The attribute name should follow the namespace convention (e.g., "user.", "system.", etc.).
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `options` - [`SetXAttrOptions`] specifying the attribute name, value, and flags
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The user is not authorized to write to the file
    /// * The filesystem does not support extended attributes
    /// * The attribute name or value is invalid
    /// * The operation fails due to system restrictions
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::SetXAttrOptionsBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rust_safe_io::options::OpenFileOptionsBuilder;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new("", "", "").unwrap().0;
    /// let dir_config = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap();
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth, "example.txt", OpenFileOptionsBuilder::default().build().unwrap()).unwrap();
    ///
    /// let options = SetXAttrOptionsBuilder::default()
    ///     .name("security.selinux".to_string())
    ///     .build()
    ///     .unwrap();
    ///
    /// file_handle.safe_set_xattr(&cedar_auth, options).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::indexing_slicing)] // function checks the length of the array before accessing an element
    pub fn safe_set_xattr(
        &self,
        cedar_auth: &CedarAuth,
        options: SetXAttrOptions,
    ) -> Result<(), RustSafeIoError> {
        let xattr_context = serde_json::json!({
            "xattr": {
                "name": &options.name
            }
        });

        is_authorized_with_context(
            cedar_auth,
            &FilesystemAction::SetXAttr,
            &FileEntity::from_string_path(&self.full_path())?,
            &xattr_context,
        )?;

        // Only support security.selinux extended attribute
        if options.name == "security.selinux" {
            // Validate user-provided SELinux components before any I/O operations
            // This prevents injection attacks via colons, whitespace, or control characters
            if let Some(ref user) = options.selinux_user {
                validate_selinux_component(user, "user")?;
            }
            if let Some(ref role) = options.selinux_role {
                validate_selinux_component(role, "role")?;
            }
            if let Some(ref stype) = options.selinux_type {
                validate_selinux_component(stype, "type")?;
            }
            if let Some(ref level) = options.selinux_level {
                validate_selinux_component(level, "level")?;
            }

            let old_xattr = get_old_xattr_value(&self.file_handle.file, &options.name)?;

            if old_xattr.is_empty() {
                return Err(RustSafeIoError::InvalidArguments {
                    reason: format!("SELinux extended attribute '{}' is empty", options.name),
                });
            }

            // Parse the existing value as a string (e.g., "user:role:type:level")
            let old_xattr_str = String::from_utf8_lossy(&old_xattr);
            let parts: Vec<&str> = old_xattr_str.split(':').collect();

            // Validate SELinux context format (user:role:type:level)
            if parts.len() != 4 {
                return Err(RustSafeIoError::InvalidArguments {
                    reason: format!(
                        "Invalid xattr format for '{}': expected 4 colon-separated components, got {}",
                        options.name,
                        parts.len()
                    ),
                });
            }

            // Build new SELinux context, using provided values or keeping existing ones
            // Format: user:role:type:level (indices 0, 1, 2, 3)
            let new_user = options.selinux_user.as_deref().unwrap_or(parts[0]);
            let new_role = options.selinux_role.as_deref().unwrap_or(parts[1]);
            let new_type = options.selinux_type.as_deref().unwrap_or(parts[2]);
            let new_level = options.selinux_level.as_deref().unwrap_or(parts[3]);

            let new_xattr = format!("{new_user}:{new_role}:{new_type}:{new_level}");

            fsetxattr(
                &self.file_handle.file,
                &options.name,
                new_xattr.as_bytes(),
                XattrFlags::empty(),
            )?;

            Ok(())
        } else {
            Err(RustSafeIoError::UnsupportedOperationError {
                reason: format!(
                    "Extended attribute for '{}' is not supported. Only 'security.selinux' is supported.",
                    options.name
                ),
            })
        }
    }
}
