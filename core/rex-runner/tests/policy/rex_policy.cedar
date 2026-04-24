// Username will be updated to your cloud desktop username (alias) for development/testing
permit(
    principal == User::"{{username}}",
    action in [
        file_system::Action::"read",
        file_system::Action::"write",
        file_system::Action::"open",
        file_system::Action::"create",
        file_system::Action::"delete"
    ],
    resource
);

permit(
    principal == User::"{{username}}",
    action in [
        file_system::Action::"open",
        file_system::Action::"create",
        file_system::Action::"delete"
    ],
    resource
);
