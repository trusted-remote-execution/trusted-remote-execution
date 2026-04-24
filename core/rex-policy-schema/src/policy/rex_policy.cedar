permit (
    principal == User::"{{username}}",
    action in
        [file_system::Action::"write",
         file_system::Action::"open",
         file_system::Action::"create",
         file_system::Action::"delete",
         file_system::Action::"read",
         file_system::Action::"chmod",
         file_system::Action::"chown",
         file_system::Action::"stat",
         file_system::Action::"move",
         file_system::Action::"execute",
         file_system::Action::"network_namespace",
         file_system::Action::"unmount"],
    resource
);

permit (
    principal == User::"{{username}}",
    action in
        [
            process_system::Action::"list",
            process_system::Action::"list_fds",
            process_system::Action::"mount_namespace",
            process_system::Action::"network_namespace"
        ],
    resource
);

