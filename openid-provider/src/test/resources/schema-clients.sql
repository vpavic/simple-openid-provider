CREATE TABLE clients (
	id VARCHAR(100) PRIMARY KEY,
	issue_date TIMESTAMP NOT NULL,
	metadata TEXT NOT NULL,
	secret VARCHAR(43),
	registration_uri VARCHAR(200),
	access_token VARCHAR(43)
);
