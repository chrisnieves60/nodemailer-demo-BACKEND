CREATE TABLE users(
    id SERIAL NOT NULL PRIMARY KEY, 
    username CHAR(30) NOT NULL, 
    email CHAR (255) NOT NULL,
    password CHAR(255) NOT NULL
);