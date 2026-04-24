use anyhow::Result;
use cedar_policy::{Entities, Entity, EntityUid, RestrictedExpression};
use cedar_policy::{EntityId, EntityTypeName};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

const USER_ENTITY_NAME: &str = "User";

/// A trait for types that can be represented as Rex entities in the permission system.
///
/// This trait provides the necessary functionality to convert Rust objects
/// into Cedar entities that can be used with the Cedar authorization system.
/// Implementing this trait allows a type to be used as a cedar entity in permission checks.
/// Read more about [Cedar Language](https://docs.cedarpolicy.com/) [Cedar Entities](https://docs.cedarpolicy.com/policies/syntax-entity.html#entity-overview).
pub trait CedarRexEntity {
    /// Returns an entity id for this entity.
    ///
    /// # Returns
    /// A String representing the ID of this entity.
    fn entity_id(&self) -> String;

    /// Returns the type name of this entity.
    ///
    /// The type name is used to categorize entities in the Rex system and
    /// should follow the Rex naming convention (e.g., "`User`").
    ///
    /// # Returns
    /// A String representing the type name of this entity.
    fn entity_name(&self) -> String;

    /// Returns the parent entities of this entity.
    ///
    /// In Rex, entities can have parent-child relationships. This method
    /// returns all parent entities of the current entity.
    ///
    /// # Returns
    /// A vector of boxed trait objects representing parent entities.
    fn parents(&self) -> Vec<&dyn CedarRexEntity>;

    /// Returns the attributes of this entity.
    ///
    /// Attributes are key-value pairs that provide additional information about the entity.
    /// This method returns a [`HashMap`] of attribute names to their corresponding values as
    /// [`RestrictedExpression`].
    ///
    /// # Returns
    /// A [`HashMap`] of attribute names to [`RestrictedExpression`] values.
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        Ok(HashMap::new())
    }

    /// Returns the tags of this entity, if any.
    ///
    /// Tags are key-value pairs that can be used in Cedar policies with the
    /// `hasTag()` and `getTag()` functions. This is used for entities defined
    /// with the `tags String` directive in the Cedar schema.
    ///
    fn get_tags(&self) -> Result<Option<Vec<(String, Value)>>> {
        Ok(None)
    }

    /// Returns the Cedar entity ID formatted for use in Cedar policies.
    ///
    /// This method formats the entity name and ID in the format required by Cedar policies:
    /// `EntityName::"EntityId"`.
    ///
    /// # Returns
    /// A String containing the formatted Cedar entity ID.
    fn cedar_eid(&self) -> String {
        format!("{}::\"{}\"", self.entity_name(), self.entity_id())
    }

    fn to_cedar_entities_vec(&self, entities: &mut Vec<Entity>) -> Result<()> {
        entities.push(self.to_cedar_entity()?);
        self.parents()
            .iter()
            .try_fold(entities, |entities, parent| -> Result<_> {
                parent.to_cedar_entities_vec(entities)?;
                Ok(entities)
            })?;
        Ok(())
    }

    /// Converts this entity and all its parent entities into an [`Entities`] collection.
    ///
    /// This method recursively collects this entity and all its ancestors
    /// into a single [`Entities`] collection that can be used for authorization checks.
    ///
    /// # Returns
    /// A Result containing the [`Entities`] collection if successful, or an error if conversion fails.
    fn to_cedar_entities(&self) -> Result<Entities> {
        let mut entities: Vec<Entity> = Vec::new();
        self.to_cedar_entities_vec(&mut entities)?;
        Ok(Entities::from_entities(entities, None)?)
    }

    /// Converts this entity into a Cedar [`Entity`] instance.
    ///
    /// This method creates a new [`Entity`] object representing this entity.
    ///
    /// # Returns
    /// A Result containing the [`Entity`] if successful, or an error if conversion fails.
    fn to_cedar_entity(&self) -> Result<Entity> {
        let cedar_entity_parents = self.parents().iter().try_fold(
            HashSet::new(),
            |mut hash_set, parent| -> Result<_> {
                hash_set.insert(EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str(&parent.entity_name())?,
                    EntityId::new(parent.entity_id()),
                ));
                Ok(hash_set)
            },
        )?;

        let entity_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(&self.entity_name())?,
            EntityId::new(self.entity_id()),
        );

        let attrs = self.get_attrs()?;
        let tags = self.get_tags()?;

        if let Some(tag_map) = tags {
            let tag_exprs: Vec<(String, RestrictedExpression)> = tag_map
                .into_iter()
                .filter_map(|(key, value)| match value {
                    Value::String(s) => Some((key, RestrictedExpression::new_string(s))),
                    _ => None,
                })
                .collect();

            let entity = Entity::new_with_tags(entity_uid, attrs, cedar_entity_parents, tag_exprs)?;
            Ok(entity)
        } else if attrs.is_empty() {
            let entity = Entity::new_no_attrs(entity_uid, cedar_entity_parents);
            Ok(entity)
        } else {
            let entity = Entity::new(entity_uid, attrs, cedar_entity_parents)?;
            Ok(entity)
        }
    }
}

/// Represents a user entity in the cedar authorization system.
///
/// [`UserEntity`] implements the [`CedarRexEntity`].
///
/// # Examples
///
/// ```no_run
/// use rex_cedar_auth::cedar_auth::{UserEntity, CedarRexEntity};
///
/// let user = UserEntity::new("user123".to_string());
/// assert_eq!(user.entity_id(), "user123");
/// assert_eq!(user.entity_name(), "User");
/// ```
#[derive(Clone, Debug)]
pub struct UserEntity {
    id: String,
}

impl UserEntity {
    pub const fn new(id: String) -> Self {
        UserEntity { id }
    }
}

impl CedarRexEntity for UserEntity {
    /// The identifier is the user id
    ///
    /// # Returns
    ///
    /// A String containing the user id
    fn entity_id(&self) -> String {
        self.id.clone()
    }

    /// The Cedar Entity type name that this struct represents
    ///
    /// # Returns
    ///
    /// A String containing Cedar Entity type name
    fn entity_name(&self) -> String {
        String::from(USER_ENTITY_NAME)
    }

    /// Returns a vector of parent entities for this user
    ///
    /// # Returns
    ///
    /// An empty vector since users have no parent entities
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cedar_auth::{CedarRexEntity, UserEntity};
    use crate::fs::entities::ArgumentsEntity;
    use anyhow::Result;
    use std::collections::HashSet;
    use uuid::Uuid;

    fn create_test_user() -> UserEntity {
        UserEntity::new("user123".to_string())
    }

    /// Given: A user entity
    /// When: Accessing the entity's properties
    /// Then: The getters return the expected values
    #[test]
    fn test_user_entity_getters() {
        let user = create_test_user();

        assert_eq!(user.entity_id(), "user123");
        assert_eq!(user.entity_name(), "User");
        assert!(user.parents().is_empty());
    }

    /// Given: A user entity
    /// When: Converting the user to a Cedar entity
    /// Then: The Cedar entity has the correct ID and type
    #[test]
    fn test_user_entity_to_entity() {
        let user = create_test_user();
        let entity = user.to_cedar_entity().expect("Failed to convert to Entity");

        assert_eq!(entity.uid().id().escaped(), "user123");
        assert_eq!(entity.uid().type_name().to_string(), "User");
    }

    /// Given: A user entity
    /// When: Converting the user to a collection of Cedar entities
    /// Then: The collection contains just one entity with the correct properties
    #[test]
    fn test_user_entity_to_entities() {
        let user = create_test_user();
        let entities = user
            .to_cedar_entities()
            .expect("Failed to convert to Entities");

        let entity_vec: Vec<_> = entities.into_iter().collect();
        assert_eq!(entity_vec.len(), 1);
        assert_eq!(entity_vec[0].uid().id().escaped(), "user123");
        assert_eq!(entity_vec[0].uid().type_name().to_string(), "User");
    }

    // For testing parent-child relationships, we need another entity type
    #[derive(Clone, Debug)]
    struct GroupEntity {
        id: String,
        users: Vec<UserEntity>,
    }

    impl GroupEntity {
        fn new(id: String, users: Vec<UserEntity>) -> Self {
            GroupEntity { id, users }
        }
    }

    impl CedarRexEntity for GroupEntity {
        fn entity_id(&self) -> String {
            self.id.clone()
        }

        fn entity_name(&self) -> String {
            String::from("Group")
        }

        fn parents(&self) -> Vec<&dyn CedarRexEntity> {
            self.users
                .iter()
                .map(|user| user as &dyn CedarRexEntity)
                .collect()
        }
    }

    /// Given: Two user entities and a group entity that has these users as parents
    /// When: Accessing the group's parents
    /// Then: The parent collection contains both users
    #[test]
    fn test_entity_with_parents() -> Result<()> {
        let user1 = UserEntity::new("user1".to_string());
        let user2 = UserEntity::new("user2".to_string());
        let group = GroupEntity::new("group1".to_string(), vec![user1, user2]);

        let parents = group.parents();
        assert_eq!(parents.len(), 2);

        let entity = group
            .to_cedar_entity()
            .expect("Failed to convert to Entity");
        let json_string1 = r#"{"uid":{"type":"Group","id":"group1"},"attrs":{},"parents":[{"type":"User","id":"user2"},{"type":"User","id":"user1"}]}"#.to_string();
        let json_string2 = r#"{"uid":{"type":"Group","id":"group1"},"attrs":{},"parents":[{"type":"User","id":"user1"},{"type":"User","id":"user2"}]}"#.to_string();
        let result_json = entity.to_json_string()?;
        assert!(
            [json_string1.clone(), json_string2.clone()].contains(&result_json),
            "Expected value to be one of ['{json_string1}', '{json_string2}', 'orange'], but got '{result_json}'"
        );

        let entities = group
            .to_cedar_entities()
            .expect("Failed to convert to Entities");

        let entity_ids: HashSet<_> = entities
            .into_iter()
            .map(|e| e.uid().id().escaped().to_string())
            .collect();
        assert_eq!(entity_ids.len(), 3); // group + 2 users

        assert!(entity_ids.contains("group1"));
        assert!(entity_ids.contains("user1"));
        assert!(entity_ids.contains("user2"));
        Ok(())
    }

    /// Given: An entity with an invalid typename containing spaces
    /// When: Converting the entity to a Cedar entity
    /// Then: The conversion fails with an error
    #[test]
    fn test_error_handling_invalid_typename() {
        struct InvalidEntity;

        impl CedarRexEntity for InvalidEntity {
            fn entity_id(&self) -> String {
                "invalid".to_string()
            }

            fn entity_name(&self) -> String {
                "Invalid Type With Spaces".to_string()
            }

            fn parents(&self) -> Vec<&dyn CedarRexEntity> {
                Vec::new()
            }
        }

        let invalid = InvalidEntity;
        let result = invalid.to_cedar_entity();

        assert!(result.is_err(), "Expected error for invalid type name");
    }

    /// Given: A user entity
    /// When: Calling the cedar_eid method
    /// Then: The method returns the correctly formatted Cedar entity ID string
    #[test]
    fn test_cedar_eid_formatting() {
        let user = UserEntity::new("test_user".to_string());
        assert_eq!(user.cedar_eid(), "User::\"test_user\"");
    }

    /// Given: A user entity which doesn't support tags
    /// When: Calling tag-related method
    /// Then: The method returns appropriate defaults
    #[test]
    fn test_user_entity_no_tags() {
        let user = UserEntity::new("user123".to_string());
        assert!(user.get_tags().unwrap().is_none());
    }

    /// Given: An entity with different tag value types
    /// When: Converting to Cedar entity using to_cedar_entity
    /// Then: Entity is created successfully with tags
    #[rstest::rstest]
    #[case::string_tags(vec![("key1", "value1"), ("key2", "value2")])]
    #[case::number_tags(vec![("count", "42"), ("size", "1024")])]
    #[case::bool_tags(vec![("enabled", "true"), ("verbose", "false")])]
    fn test_entity_creation_with_tags(#[case] tags: Vec<(&str, &str)>) -> Result<()> {
        let args: Vec<(String, Option<String>)> = tags
            .into_iter()
            .map(|(key, value)| (key.to_string(), Some(value.to_string())))
            .collect();
        let entity = ArgumentsEntity::new(args);

        let cedar_entity = entity.to_cedar_entity()?;
        // Entity ID should be a valid UUID
        assert!(
            Uuid::parse_str(&cedar_entity.uid().id().escaped()).is_ok(),
            "Entity ID should be a valid UUID"
        );
        Ok(())
    }

    // Hierarchical entity for testing recursive parent relationships
    #[derive(Clone, Debug)]
    struct HierarchicalEntity {
        id: String,
        parent: Option<Box<HierarchicalEntity>>,
    }

    impl HierarchicalEntity {
        fn new(id: String, parent: Option<Box<HierarchicalEntity>>) -> Self {
            HierarchicalEntity { id, parent }
        }
    }

    impl CedarRexEntity for HierarchicalEntity {
        fn entity_id(&self) -> String {
            self.id.clone()
        }

        fn entity_name(&self) -> String {
            String::from("Hierarchical")
        }

        fn parents(&self) -> Vec<&dyn CedarRexEntity> {
            match &self.parent {
                Some(parent) => vec![parent.as_ref() as &dyn CedarRexEntity],
                None => vec![],
            }
        }
    }

    /// Given: A hierarchical entity structure with multiple levels of parents
    /// When: Calling to_cedar_entities_vec on the deepest entity
    /// Then: All entities in the hierarchy are collected in the vector
    #[test]
    fn test_to_cedar_entities_vec_with_multiple_hierarchy_levels() -> Result<()> {
        // Create a 4-level hierarchy: root -> level1 -> level2 -> level3
        let root = HierarchicalEntity::new("root".to_string(), None);
        let level1 = HierarchicalEntity::new("level1".to_string(), Some(Box::new(root)));
        let level2 = HierarchicalEntity::new("level2".to_string(), Some(Box::new(level1)));
        let level3 = HierarchicalEntity::new("level3".to_string(), Some(Box::new(level2)));

        let mut entity_vec: Vec<cedar_policy::Entity> = Vec::new();
        level3.to_cedar_entities_vec(&mut entity_vec)?;
        assert_eq!(
            entity_vec.len(),
            4,
            "Should have collected all 4 entities in the hierarchy"
        );
        let entity_ids: HashSet<_> = entity_vec
            .iter()
            .map(|e| e.uid().id().escaped().to_string())
            .collect();
        assert!(entity_ids.contains("root"), "Root entity should be present");
        assert!(
            entity_ids.contains("level1"),
            "Level 1 entity should be present"
        );
        assert!(
            entity_ids.contains("level2"),
            "Level 2 entity should be present"
        );
        assert!(
            entity_ids.contains("level3"),
            "Level 3 entity should be present"
        );

        for entity in &entity_vec {
            assert_eq!(
                entity.uid().type_name().to_string(),
                "Hierarchical",
                "All entities should have type 'Hierarchical'"
            );
        }

        Ok(())
    }

    /// Given: A hierarchical entity structure with multiple levels
    /// When: Calling to_cedar_entities (which uses to_cedar_entities_vec internally)
    /// Then: Returns an Entities collection containing all entities in the hierarchy
    #[test]
    fn test_to_cedar_entities_with_deep_hierarchy() -> Result<()> {
        // Create a 5-level deep hierarchy
        let mut current = HierarchicalEntity::new("level0".to_string(), None);
        for i in 1..=4 {
            current = HierarchicalEntity::new(format!("level{}", i), Some(Box::new(current)));
        }

        let entities = current.to_cedar_entities()?;
        let entity_vec: Vec<_> = entities.into_iter().collect();
        assert_eq!(entity_vec.len(), 5, "Should have collected all 5 entities");
        let entity_ids: HashSet<_> = entity_vec
            .iter()
            .map(|e| e.uid().id().escaped().to_string())
            .collect();

        for i in 0..=4 {
            assert!(
                entity_ids.contains(&format!("level{}", i)),
                "Level {} entity should be present",
                i
            );
        }

        Ok(())
    }
}
