CREATE TABLE refresh_tokens (
	token VARCHAR(43) PRIMARY KEY,
	client_id VARCHAR(100) NOT NULL,
	subject VARCHAR(30) NOT NULL,
	scope VARCHAR(200) NOT NULL,
	expiry BIGINT NOT NULL,
	UNIQUE (client_id, subject)
);
