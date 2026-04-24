// Allow opening the specific directory
permit(
    principal,
    action in [file_system::Action::"open"],
    resource == file_system::Dir::"/usr/share/misc"
);

// Allow opening and reading the specific file
permit(
    principal,
    action in [file_system::Action::"open", file_system::Action::"read"],
    resource == file_system::File::"/usr/share/misc/ascii"
);
