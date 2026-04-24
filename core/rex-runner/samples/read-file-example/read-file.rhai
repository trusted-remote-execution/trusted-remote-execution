let dir_handle = DirConfig()
    .path(directory_path)
    .build()
    .open(OpenDirOptions().build());

let file_handle = dir_handle.open_file(
    file_name,
    OpenFileOptions().read(true).build(),
);

let content = file_handle.read();
info("Read " + content.len() + " bytes");
content
