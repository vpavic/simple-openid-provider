CREATE TABLE op_jwk_set (
	jwk_set TEXT NOT NULL
);

CREATE TABLE op_clients (
	id VARCHAR(100) PRIMARY KEY,
	issue_date TIMESTAMP NOT NULL,
	metadata TEXT NOT NULL,
	secret VARCHAR(43),
	registration_uri VARCHAR(200),
	access_token VARCHAR(43)
);

CREATE TABLE op_refresh_tokens (
	token VARCHAR(43) PRIMARY KEY,
	principal VARCHAR(30) NOT NULL,
	client_id VARCHAR(100) NOT NULL,
	scope VARCHAR(200) NOT NULL,
	expiry BIGINT NOT NULL
);
