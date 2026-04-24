// Username will be updated to your cloud desktop username (alias) for development/testing
permit(
    principal == User::"{{username}}",
    action in [
        process_system::Action::"list"
    ],
    resource
);