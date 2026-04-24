use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntityType {
    Sysctl,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let type_str = match self {
            EntityType::Sysctl => "sysctl::Sysctl",
        };

        write!(f, "{type_str}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;

    /// Given: An entity type to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::sysctl(EntityType::Sysctl, "sysctl::Sysctl")]
    fn test_entity_type_formats(
        #[case] entity_type: EntityType,
        #[case] type_str: String,
    ) -> Result<()> {
        assert_eq!(entity_type.to_string(), type_str);
        Ok(())
    }
}
