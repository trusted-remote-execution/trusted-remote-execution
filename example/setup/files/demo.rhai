let content = cat("/tmp/rex_example/hello.txt");
info(`File says: ${content}`);

let files = ls("/tmp/rex_example");
info(`Directory listing: ${files}`);
