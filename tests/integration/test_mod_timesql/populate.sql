CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255),
  `password` VARCHAR(255),
  `mail` VARCHAR(255)
);

INSERT INTO `users` (`name`, `password`, `mail`)
VALUES ('Karl', '123456', 'karl@mail.com'),
       ('Linda', 'my5cr3t3P455w0rd', 'adnil@internet.tech'),
       ('John', 'adminIGuess', 'john.doe@nowhere.abc');
