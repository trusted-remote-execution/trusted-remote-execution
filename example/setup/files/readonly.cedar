// Read-only access to files under /tmp/rex_example
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
    ],
    resource
) when {
    resource in file_system::Dir::"/tmp/rex_example"
};
