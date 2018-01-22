CREATE TABLE refresh_tokens (
	token VARCHAR(43) PRIMARY KEY,
	client_id VARCHAR(36) NOT NULL,
	subject VARCHAR(36) NOT NULL,
	scope VARCHAR(1000) NOT NULL,
	expiry BIGINT NOT NULL,
	UNIQUE (client_id, subject)
);
