// Username will be updated to your cloud desktop username (alias) for development/testing
permit(
    principal == User::"{{username}}",
    action == file_system::Action::"read",
    resource == "/proc/meminfo",
);
