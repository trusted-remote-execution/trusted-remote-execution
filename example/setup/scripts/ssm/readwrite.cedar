// Read-write Cedar policy for Rex SSM documents.
// Deploy to /opt/rex/policies/readwrite.cedar on the managed instance.
//
// Grants: full file operations on /tmp/rex plus system info and process listing.
// Network and sysctl operations are not included — add as needed.

// Full file operations under /tmp/rex
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"write",
        file_system::Action::"create",
        file_system::Action::"delete",
        file_system::Action::"stat",
        file_system::Action::"chmod",
        file_system::Action::"chown",
        file_system::Action::"move",
        file_system::Action::"execute"
    ],
    resource
) when {
    resource in file_system::Dir::"/tmp/rex" ||
    resource == file_system::Dir::"/tmp/rex"
};

// Parent directory access for opening /tmp
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat",
        file_system::Action::"create"
    ],
    resource
) when {
    resource == file_system::Dir::"/tmp" ||
    resource == file_system::File::"/tmp"
};

// Read-only access to /proc for system info commands
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
    ],
    resource
) when {
    resource in file_system::Dir::"/proc" ||
    resource == file_system::Dir::"/proc" ||
    resource == file_system::File::"/proc"
};

// Read-only access to /usr/bin for execute
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat",
        file_system::Action::"execute"
    ],
    resource
) when {
    resource in file_system::Dir::"/usr/bin" ||
    resource == file_system::Dir::"/usr/bin"
};

// Sysinfo operations (hostname, nproc, free, uname)
permit(
    principal,
    action in [
        sysinfo::Action::"list",
        sysinfo::Action::"resolve_hostname"
    ],
    resource
);

// Process listing (ps)
permit(
    principal,
    action in [
        process_system::Action::"list",
        process_system::Action::"list_fds"
    ],
    resource
);

// Stat access for df
permit(
    principal,
    action in [
        file_system::Action::"stat"
    ],
    resource
);

// Network operations (curl, resolve)
permit(
    principal,
    action in [
        network::Action::"GET",
        network::Action::"connect"
    ],
    resource
) when {
    resource.url like "https://*" ||
    resource.url like "http://*"
};
