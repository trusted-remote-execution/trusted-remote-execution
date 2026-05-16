// Policy for /private/tmp/rex-example — managed by service owner
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat",

        // --- Uncomment below to allow write operations ---
        // file_system::Action::"write"
    ],
    resource
) when {
    resource in file_system::Dir::"/private/tmp/rex-example"
};
