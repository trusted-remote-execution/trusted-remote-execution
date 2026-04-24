// Attempt to create and write a file, then read it back
let path = "/tmp/rex_example/written.txt";
touch(path);
replace(path, "Hello from write-test!");
let content = cat(path);
info(`Wrote and read back: ${content}`);
