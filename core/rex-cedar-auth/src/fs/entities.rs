use crate::cedar_auth::CedarRexEntity;
use crate::fs::types::EntityType::{Dir, File};
use anyhow::Result;
use cedar_policy::RestrictedExpression;
use serde_json::Value;
use std::collections::HashMap;
use std::{path::Path, path::PathBuf};
use uuid::Uuid;

/// Represents a directory entity in the Cedar authorization system.
///
/// [`DirEntity`] implements the [`CedarRexEntity`] to model directories as entities.
/// Each directory has a file system path and potentially a parent directory.
/// The hierarchy of directories in the file system is reflected in the
/// parent-child relationships of the entities.
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `path` | `String` | Absolute file system path |
///
/// # Example Policy
///
/// ```cedar
/// // Unrestricted access to all directories
/// permit(
///   principal,
///   action,
///   resource is file_system::Dir
/// );
///
/// // Scoped to specific directories
/// permit(
///   principal,
///   action,
///   resource is file_system::Dir
/// ) when {
///   [
///     file_system::Dir::"/var/log",
///     file_system::Dir::"/etc",
///   ].contains(resource)
/// };
/// ```
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use rex_cedar_auth::cedar_auth::CedarRexEntity;
/// use rex_cedar_auth::fs::entities::{DirEntity, FileEntity};
///
/// let dir = DirEntity::new(Path::new("/home/user/documents"));
/// ```
#[derive(Clone, Debug)]
pub struct DirEntity {
    path: PathBuf,
    parent: Option<Box<DirEntity>>,
}

impl CedarRexEntity for DirEntity {
    /// The identifier is the string representation of the directory's path.
    ///
    /// # Returns
    ///
    /// A String containing the directory path
    fn entity_id(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    /// The Cedar Entity type name that this struct represents
    ///
    /// # Returns
    ///
    /// A String containing Cedar Entity type name
    fn entity_name(&self) -> String {
        Dir.to_string()
    }

    /// Returns the parent entity of this directory.
    ///
    /// If this directory has a parent directory, it is returned as a parent entity.
    /// Otherwise, an empty vector is returned.
    ///
    /// # Returns
    ///
    /// A vector containing the parent directory as a [`CedarRexEntity`]
    /// or an empty vector if there is no parent
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        self.parent.as_ref().map_or_else(Vec::new, |dir| {
            let parent_trait: &dyn CedarRexEntity = dir.as_ref();
            vec![parent_trait]
        })
    }

    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "path".to_string(),
            RestrictedExpression::new_string(self.path.to_string_lossy().to_string()),
        );
        Ok(attrs)
    }
}

impl DirEntity {
    /// Creates a new [`DirEntity`] from a file system path.
    ///
    /// This constructor validates the provided path and recursively creates
    /// parent directory entities for each component of the path.
    ///
    /// # Parameters
    ///
    /// * `path` - A reference to a `Path` object representing the directory location
    ///
    /// # Returns
    ///
    /// A Result containing the new [`DirEntity`] if successful, or an error if the path is invalid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is not absolute
    /// - The path contains relative components like ".."
    pub fn new(path: &Path) -> Result<Self> {
        validate_path(path)?;
        let path = remove_trailing_slash_from_path(path);
        let parent = path
            .parent()
            .map(|parent_path| DirEntity::new(parent_path).map(Box::new))
            .transpose()?;
        Ok(Self { path, parent })
    }
}

/// Represents a file entity in the cedar authorization system.
///
/// [`FileEntity`] implements the [`CedarRexEntity`] to model files as entities
/// within the cedar permissions framework. Each file has a file system path
/// and a parent directory. Files inherit permissions from their parent directories.
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `path` | `String` | Absolute file system path |
///
/// # Example Policy
///
/// ```cedar
/// // Unrestricted access to all files
/// permit(
///   principal,
///   action,
///   resource is file_system::File
/// );
///
/// // Scoped to specific files
/// permit(
///   principal,
///   action,
///   resource is file_system::File
/// ) when {
///   [
///     file_system::File::"/proc/meminfo",
///     file_system::File::"/proc/mounts",
///     file_system::File::"/appdata/db/postgresql.conf",
///   ].contains(resource)
/// };
/// ```
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use rex_cedar_auth::fs::entities::{DirEntity, FileEntity};
/// use rex_cedar_auth::cedar_auth::CedarRexEntity;
///
/// let file = FileEntity::new(Path::new("/home/file.txt"));
/// ```
#[derive(Clone, Debug)]
pub struct FileEntity {
    path: PathBuf,
    parent: DirEntity,
}

impl FileEntity {
    pub fn from_string_path(path: &str) -> Result<Self> {
        Self::new(Path::new(path))
    }

    /// Creates a new [`FileEntity`] from a file system path.
    ///
    /// This constructor validates the provided path, extracts the parent directory,
    /// and creates both a file entity and its parent directory entity.
    ///
    /// # Parameters
    ///
    /// * `path` - A reference to a Path object representing the file location
    ///
    /// # Returns
    ///
    /// A Result containing the new [`FileEntity`] if successful, or an error if the path is invalid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is not absolute
    /// - The path contains relative components like ".."
    /// - The path has no parent directory
    pub fn new(path: &Path) -> Result<Self> {
        validate_path(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("No parent path"))?;
        let parent = DirEntity::new(parent_path)?;
        Ok(Self {
            path: path.to_owned(),
            parent,
        })
    }
}

impl CedarRexEntity for FileEntity {
    /// The identifier is the string representation of the file's path.
    ///
    /// # Returns
    ///
    /// A String containing the file path
    fn entity_id(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    /// The Cedar Entity type name that this struct represents
    ///
    /// # Returns
    ///
    /// A String containing Cedar Entity type name
    fn entity_name(&self) -> String {
        File.to_string()
    }

    /// Returns the parent entity of this file.
    ///
    /// A file always has its parent directory as its parent entity.
    ///
    /// # Returns
    ///
    /// A vector containing the parent directory as a `CedarRexEntity` object
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        vec![&self.parent]
    }

    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "path".to_string(),
            RestrictedExpression::new_string(self.path.to_string_lossy().to_string()),
        );
        Ok(attrs)
    }
}

const INVALID_CHARS: [char; 7] = ['<', '>', '"', '|', '?', '*', '\0'];

/// Checks the path for traversal and returns an error
/// if path traversal is detected.
/// n.b. - this is not safe from TOCTOU detection of
/// symlinks and is only used to detect a path traversal in a path name like "../dir".
///
/// # Parameters
///
/// * `path` - A reference to the Path to validate
///
/// # Returns
///
/// Ok(()) if the path is valid, or an Error if validation fails
///
/// # Errors
///
/// Returns an error if:
/// - The path is not absolute (must start from the root)
/// - The path contains parent directory traversals ("..")
fn validate_path(path: &Path) -> Result<()> {
    if path
        .to_string_lossy()
        .chars()
        .any(|c| c < ' ' || INVALID_CHARS.contains(&c))
    {
        return Err(anyhow::anyhow!(
            "Path contains invalid characters {}",
            path.to_string_lossy()
        ));
    }
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "Path is not absolute {}",
            path.to_string_lossy()
        ));
    }
    if path.iter().any(|component| component == "..") {
        return Err(anyhow::anyhow!(
            "Path traversal detected {}",
            path.to_string_lossy()
        ));
    }
    Ok(())
}

/// Removes trailing slash from a path while preserving the root path "/"
fn remove_trailing_slash_from_path(path: &Path) -> PathBuf {
    match path.to_string_lossy().as_ref() {
        "/" => PathBuf::from("/"),
        p => PathBuf::from(p.strip_suffix('/').unwrap_or(p)),
    }
}

const ARGUMENTS_ENTITY_NAME: &str = "file_system::Arguments";
const ENVIRONMENT_ENTITY_NAME: &str = "file_system::Environment";

/// Represents an `Arguments` entity in the Cedar authorization system.
///
/// [`ArgumentsEntity`] implements the [`CedarRexEntity`] trait to model
/// arguments as entities with tags. This entity is used to pass arguments
/// through the Cedar authorization context for file execution operations.
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `keys` | `Set<String>` | Named argument keys (e.g., `--verbose`, `--output`) |
/// | `flags` | `Set<String>` | Flag arguments starting with `-` or `--` |
/// | `positional_values` | `Set<String>` | Positional argument values |
///
/// # Tags
///
/// Arguments are also available as tags for use with `hasTag()` and `getTag()`:
/// - Named arguments: `context.arguments.getTag("--verbose")` returns the value
/// - Positional arguments: `context.arguments.getTag("$ARG0")` returns the first positional value
/// - Flag presence: `context.arguments.hasTag("/home/user")` checks if argument exists
///
/// NB: Always call `hasTag()` before `getTag()` to check if a tag exists to avoid policy evaluation errors.
///
/// # Example Policy
///
/// ```cedar
/// // Allow execution with any arguments
/// permit(
///   principal,
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/sbin/iptables"
/// );
///
/// // Validate iptables command arguments (exact value and allowed list)
/// permit(
///   principal == User::"netadmin",
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/sbin/iptables"
/// ) when {
///   context.arguments.hasTag("-A") && context.arguments.getTag("-A") == "INPUT" &&
///   context.arguments.hasTag("-p") && context.arguments.getTag("-p") in ["tcp", "udp"] &&
///   context.arguments.hasTag("--dport") && context.arguments.getTag("--dport") == "8000" &&
///   context.arguments.hasTag("-j") && context.arguments.getTag("-j") in ["ACCEPT", "DROP"]
/// };
///
/// // Check argument existence and wildcard matching
/// permit(
///   principal,
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/bin/command"
/// ) when {
///   context.arguments.hasTag("--file") &&
///   context.arguments.hasTag("--ip") && context.arguments.getTag("--ip") like "192.168.1.*"
/// };
///
/// // Check required arguments by type
/// permit(
///   principal,
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/bin/command"
/// ) when {
///   ["--output"].containsAll(context.arguments.keys) &&
///   ["--verbose"].containsAll(context.arguments.flags) &&
///   ["/tmp/input.txt"].containsAll(context.arguments.positional_values)
/// };
/// ```
///
/// # Fields
///
/// * `id` - A unique identifier for this entity (UUID)
/// * `tags` - All arguments stored as key-value pairs. For named arguments, the key is the
///   argument name. For positional arguments, the key is `$ARG{index}` where index starts at 0.
/// * `names` - Only the real argument names from named arguments. This field excludes the
///   generated `$ARG*` keys used for positional arguments. This distinction ensures that
///   Cedar policies can distinguish between user-provided argument names and system-generated
///   positional argument keys.
#[derive(Clone, Debug)]
pub struct ArgumentsEntity {
    id: String,
    tags: Vec<(String, Value)>,
    keys: Vec<String>,
    flags: Vec<String>,
    positional_values: Vec<String>,
}

impl ArgumentsEntity {
    /// Creates a new `ArgumentsEntity` from raw argument data.
    ///
    /// This constructor processes raw arguments and internally constructs both the tags
    /// (for Cedar's `hasTag()`/`getTag()` functions) and the names list (for the `names` attribute).
    ///
    /// # Parameters
    ///
    /// * `args` - Vector of (key, `Option<value>`) tuples where:
    ///   - `(key, Some(value))` represents a named argument (e.g., `--verbose`, `true`)
    ///   - `(key, None)` represents a positional argument (e.g., `input.txt`)
    ///
    /// # Returns
    ///
    /// A new `ArgumentsEntity` with:
    /// - `tags` containing all arguments (named with original keys, positional with `$ARG{index}` keys)
    /// - `names` containing only the keys from named arguments (excludes `$ARG*` keys)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use rex_cedar_auth::fs::entities::ArgumentsEntity;
    ///
    /// // Named arguments only
    /// let args = vec![
    ///     ("--verbose".to_string(), Some("true".to_string())),
    ///     ("--output".to_string(), Some("/tmp/out".to_string())),
    /// ];
    /// let entity = ArgumentsEntity::new(args);
    /// // tags: {"--verbose": "true", "--output": "/tmp/out"}
    /// // names: ["--verbose", "--output"]
    ///
    /// // Positional arguments only
    /// let args = vec![
    ///     ("input.txt".to_string(), None),
    ///     ("output.txt".to_string(), None),
    /// ];
    /// let entity = ArgumentsEntity::new(args);
    /// // tags: {"$ARG0": "input.txt", "$ARG1": "output.txt"}
    /// // names: []
    ///
    /// // Mixed arguments
    /// let args = vec![
    ///     ("input.txt".to_string(), None),
    ///     ("--verbose".to_string(), Some("true".to_string())),
    ///     ("output.txt".to_string(), None),
    /// ];
    /// let entity = ArgumentsEntity::new(args);
    /// // tags: {"$ARG0": "input.txt", "--verbose": "true", "$ARG1": "output.txt"}
    /// // names: ["--verbose"]
    /// ```
    #[must_use]
    pub fn new(args: Vec<(String, Option<String>)>) -> Self {
        let mut tags = Vec::new();
        let mut keys = Vec::new();
        let mut flags = Vec::new();
        let mut positional_values = Vec::new();
        let mut positional_index = 0;

        for (key, value) in args {
            if let Some(val) = value {
                tags.push((key.clone(), Value::String(val)));
                keys.push(key.clone());
            } else {
                let generated_key = format!("$ARG{positional_index}");
                tags.push((generated_key, Value::String(key.clone())));
                tags.push((key.clone(), Value::String("true".to_string())));

                if key.starts_with('-') {
                    flags.push(key);
                } else {
                    positional_values.push(key);
                }

                positional_index += 1;
            }
        }

        ArgumentsEntity {
            id: Uuid::new_v4().to_string(),
            tags,
            keys,
            flags,
            positional_values,
        }
    }
}

impl CedarRexEntity for ArgumentsEntity {
    /// The identifier is the entity ID.
    fn entity_id(&self) -> String {
        self.id.clone()
    }

    /// The Cedar Entity type name that this struct represents.
    fn entity_name(&self) -> String {
        String::from(ARGUMENTS_ENTITY_NAME)
    }

    /// Arguments entities have no parent entities in the hierarchy.
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this entity, including:
    /// - `keys`: all argument names (excludes `$ARG*` keys)
    /// - `flags`: arguments that start with - or --
    /// - `positional`: arguments that don't start with - or --
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();

        // Convert keys to RestrictedExpression
        let keys_exprs: Vec<RestrictedExpression> = self
            .keys
            .iter()
            .map(|name| RestrictedExpression::new_string(name.clone()))
            .collect();

        // Convert flags to RestrictedExpression
        let flags_exprs: Vec<RestrictedExpression> = self
            .flags
            .iter()
            .map(|flag| RestrictedExpression::new_string(flag.clone()))
            .collect();

        // Convert positional args to RestrictedExpression
        let positional_values_exprs: Vec<RestrictedExpression> = self
            .positional_values
            .iter()
            .map(|arg| RestrictedExpression::new_string(arg.clone()))
            .collect();

        // Add all collections to attributes
        attrs.insert(
            "keys".to_string(),
            RestrictedExpression::new_set(keys_exprs),
        );
        attrs.insert(
            "flags".to_string(),
            RestrictedExpression::new_set(flags_exprs),
        );
        attrs.insert(
            "positional_values".to_string(),
            RestrictedExpression::new_set(positional_values_exprs),
        );

        Ok(attrs)
    }

    /// Tags represent arguments that can be checked in Cedar policies
    /// using the `hasTag()` and `getTag()` functions.
    fn get_tags(&self) -> Result<Option<Vec<(String, Value)>>> {
        Ok(Some(self.tags.clone()))
    }
}

/// Represents an `Environment` entity in the Cedar authorization system.
///
/// [`EnvironmentEntity`] implements the [`CedarRexEntity`] trait to model environment
/// variables as entities with tags. This entity is used to pass environment variables
/// through the Cedar authorization context for file execution operations. Each environment
/// variable is stored as a tag, allowing Cedar policies to check for specific environment
/// variables using the `hasTag()` and `getTag()` functions.
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `names` | `Set<String>` | Set of all environment variable names |
///
/// # Tags
///
/// Environment variables are available as tags:
/// - `context.environment.hasTag("PATH")` checks if PATH is set
/// - `context.environment.getTag("HOME")` returns the value of HOME
///
/// NB: Always call `hasTag()` before `getTag()` to check if a tag exists to avoid policy evaluation errors.
///
/// # Example Policy
///
/// ```cedar
/// // Allow execution with any environment variables
/// permit(
///   principal,
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/sbin/iptables"
/// );
///
/// // Check environment variable value and existence
/// permit(
///   principal == User::"netadmin",
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/sbin/iptables"
/// ) when {
///   context.environment.hasTag("LANG") && context.environment.getTag("LANG") == "en_US.UTF-8" &&
///   context.environment.hasTag("PATH")
/// };
///
/// // Check required environment variables
/// permit(
///   principal,
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/bin/command"
/// ) when {
///   ["LANG", "PATH"].containsAll(context.environment.names)
/// };
///
/// // Validate PATH contains safe directories
/// permit(
///   principal,
///   action == file_system::Action::"execute",
///   resource == file_system::File::"/usr/bin/command"
/// ) when {
///   context.environment.hasTag("PATH") &&
///   context.environment.getTag("PATH") like "/usr/bin*"
/// };
/// ```
#[derive(Clone, Debug)]
pub struct EnvironmentEntity {
    id: String,
    tags: Vec<(String, Value)>,
}

impl EnvironmentEntity {
    /// Creates a new `EnvironmentEntity` from environment variables.
    ///
    /// This constructor processes environment variables and internally constructs the tags
    /// (for Cedar's `hasTag()`/`getTag()` functions) and the `names` attribute.
    ///
    /// # Parameters
    ///
    /// * `env_vars` - Vector of (name, value) pairs representing environment variables
    ///
    /// # Returns
    ///
    /// A new `EnvironmentEntity` with:
    /// - `tags` containing all environment variables
    /// - `names` attribute derived from the variable names
    ///
    /// # Examples
    ///
    /// ```
    /// use rex_cedar_auth::fs::entities::EnvironmentEntity;
    ///
    /// let env_vars = vec![
    ///     ("PATH".to_string(), "/usr/bin".to_string()),
    ///     ("HOME".to_string(), "/home/user".to_string()),
    /// ];
    /// let entity = EnvironmentEntity::new(env_vars);
    /// // tags: {"PATH": "/usr/bin", "HOME": "/home/user"}
    /// // names: ["PATH", "HOME"]
    /// ```
    #[must_use]
    pub fn new(env_vars: Vec<(String, String)>) -> Self {
        let tags: Vec<(String, Value)> = env_vars
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();

        EnvironmentEntity {
            id: Uuid::new_v4().to_string(),
            tags,
        }
    }
}

impl CedarRexEntity for EnvironmentEntity {
    /// The identifier is the entity ID.
    fn entity_id(&self) -> String {
        self.id.clone()
    }

    /// The Cedar Entity type name that this struct represents.
    fn entity_name(&self) -> String {
        String::from(ENVIRONMENT_ENTITY_NAME)
    }

    /// Environment entities have no parent entities in the hierarchy.
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this entity, including the `names` attribute
    /// which contains a set of all environment variable names (keys).
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();

        // Extract variable names from tags
        let names: Vec<RestrictedExpression> = self
            .tags
            .iter()
            .map(|(name, _)| RestrictedExpression::new_string(name.clone()))
            .collect();

        attrs.insert("names".to_string(), RestrictedExpression::new_set(names));
        Ok(attrs)
    }

    /// Tags represent environment variables that can be checked in Cedar policies
    /// using the `hasTag()` and `getTag()` functions.
    fn get_tags(&self) -> Result<Option<Vec<(String, Value)>>> {
        Ok(Some(self.tags.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::CedarRexEntity;
    use anyhow::{Ok, Result};
    use rex_test_utils::assertions::assert_error_contains;
    use rex_test_utils::io::{create_file_with_content, create_temp_dir_and_path};
    use rstest::rstest;
    use serde_json::json;
    use std::fs;
    use std::path::Path;

    fn find_tag_value(tags: &Vec<(String, Value)>, key: &str) -> Value {
        tags.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("Tag '{}' not found", key))
    }

    /// Given: Valid paths
    /// When: The path is validated using validate_path
    /// Then: Validation succeeds
    #[rstest]
    #[case("/absolute/path")]
    #[case("/")]
    #[case("/absolute/path/with/numbers123")]
    #[case("/absolute/path/with/symbols-_.")]
    #[case("/sys/dev/block/259:0")]
    fn test_validate_path_with_valid_path(#[case] path: &str) {
        let result = validate_path(Path::new(path));
        assert!(
            result.is_ok(),
            "Expected path '{}' to be valid, but got error: {:?}",
            path,
            result.err()
        );
    }

    /// Given: Invalid paths for cedar authorization
    /// When: The path is validated using validate_path
    /// Then: An error is returned with the appropriate error message
    #[rstest]
    #[case("relative/path", "not absolute")]
    #[case("..", "not absolute")]
    #[case("/path/../with/traversal", "traversal detected")]
    #[case("/path/with/invalid\0char", "invalid characters")]
    #[case("/path/with/invalid<char", "invalid characters")]
    #[case("/path/with/invalid>char", "invalid characters")]
    #[case("/path/with/invalid\"char", "invalid characters")]
    #[case("/path/with/invalid|char", "invalid characters")]
    #[case("/path/with/invalid?char", "invalid characters")]
    #[case("/path/with/invalid*char", "invalid characters")]
    #[case("/path/with/invalid\u{1F}control", "invalid characters")]
    fn test_validate_path_with_invalid_path(#[case] path: &str, #[case] error_msg: &str) {
        let result = validate_path(Path::new(path));
        assert!(
            result.is_err(),
            "Expected path '{}' to be invalid, but it was valid",
            path
        );
        assert_error_contains(result, error_msg);
    }

    /// Given: Different types of paths including root and nested paths with trailing slashes
    /// When: Removing trailing slashes from these paths
    /// Then: Root path should remain unchanged and other paths should have trailing slashes removed
    #[test]
    fn test_remove_trailing_slash_from_path() {
        assert_eq!(
            remove_trailing_slash_from_path(Path::new("/")),
            PathBuf::from("/")
        );
        assert_eq!(
            remove_trailing_slash_from_path(Path::new("/path/to/dir/")),
            PathBuf::from("/path/to/dir")
        );
        assert_eq!(
            remove_trailing_slash_from_path(Path::new("/path/to/dir")),
            PathBuf::from("/path/to/dir")
        );
    }

    /// Given: The root directory path
    /// When: Creating a DirEntity for the root
    /// Then: The entity should have the correct id and no parents
    #[test]
    fn test_dir_entity_root() {
        let dir_entity = DirEntity::new(Path::new("/")).expect("Failed to create DirEntity");
        assert_eq!(dir_entity.entity_id(), "/");

        let parents = dir_entity.parents();
        assert_eq!(parents.len(), 0);
    }

    /// Given: Invalid directory paths (relative and containing path traversal)
    /// When: Attempting to create DirEntity instances with these paths
    /// Then: The creation should fail with errors
    #[test]
    fn test_dir_entity_invalid_path() {
        let result = DirEntity::new(Path::new("relative/path"));
        assert!(result.is_err());

        let result = DirEntity::new(Path::new("/valid/../invalid"));
        assert!(result.is_err());
    }

    /// Given: A DirEntity with a valid path
    /// When: Calling get_attrs()
    /// Then: The returned attributes should contain a path attribute with correct value
    #[test]
    fn test_dir_entity_get_attrs() -> Result<()> {
        let test_path = "/tmp/test";
        let dir = DirEntity::new(Path::new(test_path))?;
        let attrs = dir.get_attrs()?;

        assert!(
            attrs.contains_key("path"),
            "Attributes should contain 'path' key"
        );

        let cedar_entity = dir.to_cedar_entity()?;
        let path_attr = cedar_entity.attr("path");
        assert!(path_attr.is_some(), "Entity should have 'path' attribute");

        let entity_json: Value = serde_json::from_str(&cedar_entity.to_json_string()?)?;
        assert_eq!(
            entity_json["attrs"]["path"],
            json!(test_path),
            "Path attribute should contain the correct value"
        );

        Ok(())
    }

    /// Given: A valid file path
    /// When: Creating a FileEntity instance
    /// Then: The entity should have the correct id and name and parents
    #[test]
    fn test_file_entity_creation() -> Result<()> {
        let (temp_dir, tmp_dir_path) = create_temp_dir_and_path()?;
        let test_file_name = "file.txt";
        let test_content = "This is test content";
        create_file_with_content(&temp_dir, test_file_name, test_content)?;

        let file_path = temp_dir.path().join(test_file_name);
        let file_path_str = file_path.to_string_lossy().to_string();
        let file_entity = FileEntity::new(&file_path).expect("Failed to create FileEntity");

        assert_eq!(file_entity.entity_id(), file_path_str);
        assert_eq!(file_entity.entity_name(), "file_system::File");

        let parents = file_entity.parents();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].entity_id(), tmp_dir_path);
        assert_eq!(parents[0].entity_name(), "file_system::Dir");

        temp_dir.close()?;
        Ok(())
    }

    /// Given: Invalid file paths (relative and containing path traversal)
    /// When: Attempting to create FileEntity instances with these paths
    /// Then: The creation should fail with errors
    #[test]
    fn test_file_entity_invalid_path() {
        let result = FileEntity::new(Path::new("relative/path/file.txt"));
        assert!(result.is_err());

        let result = FileEntity::new(Path::new("/valid/../invalid/file.txt"));
        assert!(result.is_err());
    }

    /// Given: A FileEntity with a valid path
    /// When: Calling get_attrs()
    /// Then: The returned attributes should contain a path attribute with correct value
    #[test]
    fn test_file_entity_get_attrs() -> Result<()> {
        let test_path = "/tmp/test.txt";
        let file = FileEntity::new(Path::new(test_path))?;
        let attrs = file.get_attrs()?;

        assert!(
            attrs.contains_key("path"),
            "Attributes should contain 'path' key"
        );

        let cedar_entity = file.to_cedar_entity()?;
        let path_attr = cedar_entity.attr("path");
        assert!(path_attr.is_some(), "Entity should have 'path' attribute");

        let entity_json: Value = serde_json::from_str(&cedar_entity.to_json_string()?)?;
        assert_eq!(
            entity_json["attrs"]["path"],
            json!(test_path),
            "Path attribute should contain the correct value"
        );

        Ok(())
    }

    /// Given: A deeply nested directory path
    /// When: Creating a DirEntity and accessing its ancestry chain
    /// Then: The entity should have the correct parent hierarchy
    #[test]
    fn test_deep_directory_hierarchy() -> Result<()> {
        let (tmp_dir, tmp_dir_path) = create_temp_dir_and_path()?;
        let mut deep_dir_path = tmp_dir.path().join("a/b/c/d/e");
        fs::create_dir_all(&deep_dir_path)?;

        let dir_entity = DirEntity::new(&deep_dir_path).expect("Failed to create deep DirEntity");

        assert_eq!(dir_entity.entity_id(), tmp_dir_path.clone() + "/a/b/c/d/e");

        let parents = dir_entity.parents();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].entity_id(), tmp_dir_path.clone() + "/a/b/c/d");

        let grandparent = parents[0].parents();
        assert_eq!(grandparent.len(), 1);
        assert_eq!(grandparent[0].entity_id(), tmp_dir_path.clone() + "/a/b/c");

        assert_eq!(dir_entity.parents().len(), 1);
        let mut parent_entity = dir_entity.parents()[0];
        while let Some(parent_path) = deep_dir_path.parent() {
            assert_eq!(parent_entity.entity_id(), parent_path.to_string_lossy());
            assert_eq!(parent_entity.entity_name(), "file_system::Dir");
            if parent_entity.entity_id() != "/" {
                assert_eq!(parent_entity.parents().len(), 1);
                parent_entity = parent_entity.parents()[0];
            }
            deep_dir_path = parent_path.to_path_buf();
        }

        tmp_dir.close()?;
        Ok(())
    }

    /// Given: A path
    /// When: Requesting a str path
    /// Then: Return the string path
    #[test]
    fn test_str_path() -> Result<()> {
        let result = FileEntity::from_string_path("/foo\0");
        assert_error_contains(result, "invalid characters");

        Ok(())
    }

    /// Given: An ArgumentsEntity with tags
    /// When: Creating the entity and accessing its properties
    /// Then: The entity should have correct id, name, tags, and no parents
    #[test]
    fn test_arguments_entity() -> Result<()> {
        let args = vec![("--verbose".to_string(), Some("true".to_string()))];
        let entity = ArgumentsEntity::new(args);

        let entity_name = entity.entity_name();
        let tags = entity.get_tags()?.unwrap();
        let tag_value = find_tag_value(&tags, "--verbose");
        let parents = entity.parents();

        assert_eq!(entity_name, "file_system::Arguments");
        assert_eq!(tag_value, json!("true"));
        assert!(parents.is_empty());
        Ok(())
    }

    /// Given: An ArgumentsEntity with multiple argument tags
    /// When: Calling get_attrs() to retrieve the keys, flags, and positional_values attribute
    /// Then: The keys, flags, and positional_values attribute should contain all argument as a set
    #[test]
    fn test_arguments_entity_get_attrs() -> Result<()> {
        let args = vec![
            ("--verbose".to_string(), Some("true".to_string())),
            ("--output".to_string(), Some("/tmp/output.txt".to_string())),
            ("count".to_string(), Some("42".to_string())),
            ("--reverse".to_string(), None),
            ("/tmp/input.txt".to_string(), None),
        ];

        let entity = ArgumentsEntity::new(args);
        let attrs = entity.get_attrs()?;
        assert!(attrs.contains_key("keys"));
        assert!(attrs.contains_key("flags"));
        assert!(attrs.contains_key("positional_values"));
        let cedar_entity = entity.to_cedar_entity()?;
        assert!(cedar_entity.attr("keys").is_some());
        assert!(cedar_entity.attr("flags").is_some());
        assert!(cedar_entity.attr("positional_values").is_some());

        Ok(())
    }

    /// Given: An ArgumentsEntity with empty tags
    /// When: Calling get_attrs() to retrieve the attributes
    /// Then: All attributes should be an empty set
    #[test]
    fn test_arguments_entity_get_attrs_empty() -> Result<()> {
        let entity = ArgumentsEntity::new(vec![]);
        let attrs = entity.get_attrs()?;
        assert!(attrs.contains_key("keys"));
        assert!(attrs.contains_key("flags"));
        assert!(attrs.contains_key("positional_values"));
        let cedar_entity = entity.to_cedar_entity()?;
        assert!(cedar_entity.attr("keys").is_some());
        assert!(cedar_entity.attr("flags").is_some());
        assert!(cedar_entity.attr("positional_values").is_some());

        Ok(())
    }

    /// Given: A vector of arguments
    /// When: Creating an ArgumentsEntity with the new constructor
    /// Then: Both tags and sets should contain all argument keys
    #[test]
    fn test_arguments_entity_constructor_named_only() -> Result<()> {
        let args = vec![
            ("--verbose".to_string(), Some("true".to_string())),
            ("--output".to_string(), Some("/tmp/out".to_string())),
            ("--count".to_string(), Some("42".to_string())),
            ("--reverse".to_string(), None),
            ("/tmp/input.txt".to_string(), None),
        ];

        let entity = ArgumentsEntity::new(args);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 7);
        assert_eq!(find_tag_value(&tags, "--verbose"), json!("true"));
        assert_eq!(find_tag_value(&tags, "--output"), json!("/tmp/out"));
        assert_eq!(find_tag_value(&tags, "--count"), json!("42"));
        assert_eq!(find_tag_value(&tags, "--reverse"), json!("true"));
        assert_eq!(find_tag_value(&tags, "/tmp/input.txt"), json!("true"));
        assert_eq!(entity.keys.len(), 3);
        assert!(entity.keys.contains(&"--verbose".to_string()));
        assert!(entity.keys.contains(&"--output".to_string()));
        assert!(entity.keys.contains(&"--count".to_string()));
        assert_eq!(entity.flags.len(), 1);
        assert!(entity.flags.contains(&"--reverse".to_string()));
        assert_eq!(entity.positional_values.len(), 1);
        assert!(
            entity
                .positional_values
                .contains(&"/tmp/input.txt".to_string())
        );

        Ok(())
    }

    /// Given: A vector of only positional arguments
    /// When: Creating an ArgumentsEntity with the new constructor
    /// Then: Tags should have $ARG* keys and parameter flag keys, names should be empty
    #[test]
    fn test_arguments_entity_constructor_positional_only() -> Result<()> {
        let args = vec![
            ("input.txt".to_string(), None),
            ("output.txt".to_string(), None),
            ("data.csv".to_string(), None),
        ];

        let entity = ArgumentsEntity::new(args);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 6); // Two tags per positional argument
        assert_eq!(find_tag_value(&tags, "$ARG0"), json!("input.txt"));
        assert_eq!(find_tag_value(&tags, "input.txt"), json!("true"));
        assert_eq!(find_tag_value(&tags, "$ARG1"), json!("output.txt"));
        assert_eq!(find_tag_value(&tags, "output.txt"), json!("true"));
        assert_eq!(find_tag_value(&tags, "$ARG2"), json!("data.csv"));
        assert_eq!(find_tag_value(&tags, "data.csv"), json!("true"));
        assert_eq!(entity.keys.len(), 0);

        Ok(())
    }

    /// Given: A vector with mixed positional and named arguments
    /// When: Creating an ArgumentsEntity with the new constructor
    /// Then: Tags should contain all arguments, names should contain only named argument keys
    #[test]
    fn test_arguments_entity_constructor_mixed() -> Result<()> {
        let args = vec![
            ("input.txt".to_string(), None),
            ("--verbose".to_string(), Some("true".to_string())),
            ("output.txt".to_string(), None),
            ("--format".to_string(), Some("json".to_string())),
        ];

        let entity = ArgumentsEntity::new(args);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 6); // 2 named + 2 positional * 2 tags each = 6 total
        assert_eq!(find_tag_value(&tags, "$ARG0"), json!("input.txt"));
        assert_eq!(find_tag_value(&tags, "input.txt"), json!("true"));
        assert_eq!(find_tag_value(&tags, "--verbose"), json!("true"));
        assert_eq!(find_tag_value(&tags, "$ARG1"), json!("output.txt"));
        assert_eq!(find_tag_value(&tags, "output.txt"), json!("true"));
        assert_eq!(find_tag_value(&tags, "--format"), json!("json"));
        assert_eq!(entity.keys.len(), 2);
        assert!(entity.keys.contains(&"--verbose".to_string()));
        assert!(entity.keys.contains(&"--format".to_string()));
        assert!(!entity.keys.contains(&"$ARG0".to_string()));
        assert!(!entity.keys.contains(&"$ARG1".to_string()));

        Ok(())
    }

    /// Given: An empty vector of arguments
    /// When: Creating an ArgumentsEntity with the new constructor
    /// Then: Both tags and names should be empty
    #[test]
    fn test_arguments_entity_constructor_empty() -> Result<()> {
        let args = vec![];
        let entity = ArgumentsEntity::new(args);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 0);
        assert_eq!(entity.keys.len(), 0);

        Ok(())
    }

    /// Given: A vector with a single named argument
    /// When: Creating an ArgumentsEntity with the new constructor
    /// Then: Both tags and names should contain the single argument
    #[test]
    fn test_arguments_entity_constructor_single_named() -> Result<()> {
        let args = vec![("--verbose".to_string(), Some("true".to_string()))];
        let entity = ArgumentsEntity::new(args);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(find_tag_value(&tags, "--verbose"), json!("true"));
        assert_eq!(entity.keys.len(), 1);
        assert!(entity.keys.contains(&"--verbose".to_string()));

        Ok(())
    }

    /// Given: A vector with a single positional argument
    /// When: Creating an ArgumentsEntity with the new constructor
    /// Then: Tags should have $ARG0 key and parameter flag key, names should be empty
    #[test]
    fn test_arguments_entity_constructor_single_positional() -> Result<()> {
        let args = vec![("input.txt".to_string(), None)];
        let entity = ArgumentsEntity::new(args);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 2); // Two tags for single positional argument
        assert_eq!(find_tag_value(&tags, "$ARG0"), json!("input.txt"));
        assert_eq!(find_tag_value(&tags, "input.txt"), json!("true"));
        assert_eq!(entity.keys.len(), 0);

        Ok(())
    }

    /// Given: An EnvironmentEntity with tags
    /// When: Creating the entity and accessing its properties
    /// Then: The entity should have correct id, name, tags, and no parents
    #[test]
    fn test_environment_entity() -> Result<()> {
        let env_vars = vec![("PATH".to_string(), "/usr/bin".to_string())];
        let entity = EnvironmentEntity::new(env_vars);

        let entity_id = entity.entity_id();
        let entity_name = entity.entity_name();
        let tags = entity.get_tags()?.unwrap();
        let tag_value = find_tag_value(&tags, "PATH");
        let parents = entity.parents();

        assert!(
            Uuid::parse_str(&entity_id).is_ok(),
            "Entity ID should be a valid UUID"
        );
        assert_eq!(entity_name, "file_system::Environment");
        assert_eq!(tag_value, json!("/usr/bin"));
        assert!(parents.is_empty());
        Ok(())
    }

    /// Given: An EnvironmentEntity with multiple environment variable tags
    /// When: Calling get_attrs() to retrieve the names attribute
    /// Then: The names attribute should contain all variable keys as a set
    #[test]
    fn test_environment_entity_get_attrs() -> Result<()> {
        let env_vars = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("USER".to_string(), "testuser".to_string()),
        ];

        let entity = EnvironmentEntity::new(env_vars);
        let attrs = entity.get_attrs()?;
        assert!(attrs.contains_key("names"));
        let cedar_entity = entity.to_cedar_entity()?;
        assert!(cedar_entity.attr("names").is_some());

        Ok(())
    }

    /// Given: An EnvironmentEntity with empty environment variables
    /// When: Calling get_attrs() to retrieve the names attribute
    /// Then: The names attribute should be an empty set
    #[test]
    fn test_environment_entity_get_attrs_empty() -> Result<()> {
        let env_vars = Vec::new();
        let entity = EnvironmentEntity::new(env_vars);
        let attrs = entity.get_attrs()?;

        assert!(attrs.contains_key("names"));
        let cedar_entity = entity.to_cedar_entity()?;
        assert!(cedar_entity.attr("names").is_some());

        Ok(())
    }

    /// Given: A Vec with environment variables
    /// When: Creating an EnvironmentEntity with the new constructor
    /// Then: Tags and names should contain all variable keys
    #[test]
    fn test_environment_entity_constructor_with_vars() -> Result<()> {
        let env_vars = vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("USER".to_string(), "testuser".to_string()),
        ];

        let entity = EnvironmentEntity::new(env_vars);
        let tags = entity.get_tags()?.unwrap();

        assert_eq!(tags.len(), 3);
        assert_eq!(find_tag_value(&tags, "PATH"), json!("/usr/bin:/bin"));
        assert_eq!(find_tag_value(&tags, "HOME"), json!("/home/user"));
        assert_eq!(find_tag_value(&tags, "USER"), json!("testuser"));
        let attrs = entity.get_attrs()?;
        assert!(attrs.contains_key("names"));

        Ok(())
    }

    /// Given: An empty Vec of environment variables
    /// When: Creating an EnvironmentEntity with the new constructor
    /// Then: Both tags and names should be empty
    #[test]
    fn test_environment_entity_constructor_empty() -> Result<()> {
        let env_vars: Vec<(String, String)> = Vec::new();

        let entity = EnvironmentEntity::new(env_vars);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 0);
        let attrs = entity.get_attrs()?;
        assert!(attrs.contains_key("names"));

        Ok(())
    }

    /// Given: A Vec with a single environment variable
    /// When: Creating an EnvironmentEntity with the new constructor
    /// Then: Both tags and names should contain the single variable
    #[test]
    fn test_environment_entity_constructor_single_var() -> Result<()> {
        let env_vars = vec![("PATH".to_string(), "/usr/bin".to_string())];

        let entity = EnvironmentEntity::new(env_vars);
        let tags = entity.get_tags()?.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(find_tag_value(&tags, "PATH"), json!("/usr/bin"));
        let attrs = entity.get_attrs()?;
        assert!(attrs.contains_key("names"));

        Ok(())
    }
}
