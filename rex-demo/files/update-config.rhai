sed([sed::i], "workers = 4", "workers = 8", "/private/tmp/rex-example/config.ini");
let content = cat("/private/tmp/rex-example/config.ini");
info(`Updated config:\n${content}`);
