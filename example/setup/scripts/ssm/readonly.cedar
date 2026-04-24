// Read-only Cedar policy for Rex SSM documents.
// Deploy to /opt/rex/policies/readonly.cedar on the managed instance.
//
// Grants: open, read, stat on files under /tmp/rex
// Denies: write, create, delete, execute, and all other actions

permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
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
        file_system::Action::"stat"
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
