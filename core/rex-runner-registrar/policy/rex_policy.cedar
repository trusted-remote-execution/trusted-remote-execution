// Username will be updated to your cloud desktop username (alias) for development/testing
permit(
    principal == Rex::User::"{{username}}",
    action in [
        Rex::Action::"safe_read_file",
        Rex::Action::"safe_write_file",
        Rex::Action::"safe_open_file",
        Rex::Action::"safe_create_file",
        Rex::Action::"safe_delete_file"
    ],
    resource
);

permit(
    principal == Rex::User::"{{username}}",
    action in [
        Rex::Action::"safe_open_dir",
        Rex::Action::"safe_create_dir",
        Rex::Action::"safe_delete_dir"
    ],
    resource
);