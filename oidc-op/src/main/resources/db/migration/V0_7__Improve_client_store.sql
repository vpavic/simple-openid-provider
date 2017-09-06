ALTER TABLE clients RENAME content TO metadata;
ALTER TABLE clients ADD issue_date TIMESTAMP NOT NULL DEFAULT now();
ALTER TABLE clients ALTER issue_date DROP DEFAULT;
ALTER TABLE clients ADD secret VARCHAR(43);
ALTER TABLE clients ADD registration_uri VARCHAR(200);
ALTER TABLE clients ADD access_token VARCHAR(43);
