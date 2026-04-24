// Read-write access to files under /tmp/rex_example
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat",
        file_system::Action::"write",
        file_system::Action::"create",
        file_system::Action::"delete",
        file_system::Action::"chmod",
        file_system::Action::"chown"
    ],
    resource
) when {
    resource in file_system::Dir::"/tmp/rex_example"
};
