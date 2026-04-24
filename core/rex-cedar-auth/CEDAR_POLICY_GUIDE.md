# Cedar Policy Guide

This guide explains how Rex Cedar entities, actions, and attributes map to
[Cedar policy language](https://docs.cedarpolicy.com/) syntax. Use it to write
policies that control what a Rex script is allowed to do.

## How It Works

Every Rex API call is authorized against a Cedar policy. The authorization
check has three parts:

| Concept | Cedar syntax | Example |
|---------|-------------|---------|
| **Who** (principal) | `principal == User::<principal>` | `User::"nobody"` |
| **What** (action) | `action == <namespace>::Action::"<verb>"` | `file_system::Action::"read"` |
| **On what** (resource) | `resource is <namespace>::<Type>` | `file_system::File` |

Optionally, a `when` clause can inspect **resource attributes** to narrow the
scope. See each entity's documentation for available attributes and example
policies.

## Namespaces

Action names are lowercase `snake_case` in Cedar policies (e.g. `NetworkNamespace` becomes `network_namespace`).

| Namespace | Entity types | Actions |
|-----------|-------------|---------|
| `file_system` | [`File`](fs::entities::FileEntity), [`Dir`](fs::entities::DirEntity) | [`FilesystemAction`](fs::actions::FilesystemAction) |
| `process_system` | [`Process`](process::entities::ProcessEntity) | [`ProcessAction`](process::actions::ProcessAction) |
| `systemd` | [`Service`](systemd::entities::ServiceEntity), [`Systemd`](systemd::entities::SystemdEntity) | [`SystemdAction`](systemd::actions::SystemdAction) |
| `network` | [`url`](network::entities::NetworkEntity) | [`NetworkAction`](network::actions::NetworkAction) |
| `sysinfo` | [`Sysinfo`](sysinfo::entities::SysinfoEntity), [`Hostname`](sysinfo::entities::HostnameEntity) | [`SysinfoAction`](sysinfo::actions::SysinfoAction) |
| `sysctl` | [`Sysctl`](sysctl::entities::SysctlEntity) | [`SysctlAction`](sysctl::actions::SysctlAction) |

## Example Policy

This policy demonstrates how resources can be scoped using resource attributes:

```cedar
// Grant access to specific files
permit(
  principal,
  action,
  resource is file_system::File
) when {
  [
    file_system::File::"/proc/meminfo",
    file_system::File::"/proc/mounts",
    file_system::File::"/appdata/db/postgresql.conf",
  ].contains(resource)
};

// Grant access to specific directories
permit(
  principal,
  action,
  resource is file_system::Dir
) when {
  [
    file_system::Dir::"/var/log",
    file_system::Dir::"/etc",
  ].contains(resource)
};

// List only nobody-owned processes
permit(
  principal,
  action == process_system::Action::"list",
  resource is process_system::Process
) when {
  resource.username == "nobody"
};

// Restart nginx only
permit(
  principal,
  action == systemd::Action::"restart",
  resource is systemd::Service
) when {
  resource.name == "nginx.service"
};

// Allow HTTP GET to health endpoints
permit(
  principal,
  action == network::Action::"GET",
  resource is network::url
) when {
  resource.url like "https://*/health"
};

// Allow querying system info
permit(
  principal,
  action == sysinfo::Action::"list",
  resource is sysinfo::Sysinfo
);

// Allow DNS resolution
permit(
  principal,
  action == sysinfo::Action::"resolve_hostname",
  resource is sysinfo::Hostname
) when {
  resource.hostname like "*host"
};

// Allow loading sysctl parameters
permit(
  principal,
  action == sysctl::Action::"load",
  resource is sysctl::Sysctl
);
```

## Scoping Actions

Actions can be scoped in three ways:

### Allow all actions
Omit the action constraint:
```cedar
permit(
  principal,
  action,
  resource is file_system::File
);
```

### Allow specific actions
Use `in` with a list:
```cedar
permit(
  principal,
  action in [
    file_system::Action::"read",
    file_system::Action::"stat",
  ],
  resource is file_system::File
);
```

### Allow all except some
Use `!=` in a `when` clause:
```cedar
permit(
  principal,
  action,
  resource is file_system::File
) when {
  action != file_system::Action::"execute"
};
```