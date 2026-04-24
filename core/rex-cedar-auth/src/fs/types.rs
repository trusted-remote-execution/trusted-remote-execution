use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntityType {
    File,
    Dir,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let type_str = match self {
            EntityType::File => "file_system::File",
            EntityType::Dir => "file_system::Dir",
        };

        write!(f, "{type_str}")
    }
}
