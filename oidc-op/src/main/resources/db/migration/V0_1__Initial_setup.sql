CREATE TABLE users (
	username VARCHAR(30) PRIMARY KEY,
	password VARCHAR(30) NOT NULL,
	enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
	username VARCHAR(30) REFERENCES users(username) ON DELETE CASCADE,
	authority VARCHAR(30) NOT NULL,
	PRIMARY KEY (username, authority)
);

CREATE TABLE clients (
	id VARCHAR(30) PRIMARY KEY,
	content TEXT NOT NULL
);
