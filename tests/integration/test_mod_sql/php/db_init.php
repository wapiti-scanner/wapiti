<?php
$db = new SQLite3('/var/www/target.sqlite', SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
// Create a table.
$db->query(
'CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "name" VARCHAR,
    "password" VARCHAR,
    "mail" VARCHAR
  )'
);
// Insert some sample data.
$db->query('INSERT INTO "users" ("name","password","mail") VALUES ("Karl", "123456", "karl@mail.com");');
$db->query('INSERT INTO "users" ("name","password","mail") VALUES ("Linda", "my5cr3t3P455w0rd", "adnil@internet.tech");');
$db->query('INSERT INTO "users" ("name","password","mail") VALUES ("John", "adminIGuess", "john.doe@nowhere.abc");');
// Close the connection
$db->close();
?>
