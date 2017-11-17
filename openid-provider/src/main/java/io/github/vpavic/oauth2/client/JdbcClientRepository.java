package io.github.vpavic.oauth2.client;

import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import javax.annotation.PostConstruct;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.apache.commons.lang3.StringUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.TypeMismatchDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;

/**
 * A JDBC implementation of {@link ClientRepository}.
 *
 * By default uses table named {@code clients} with the following definition:
 *
 * <pre class="code">
 * CREATE TABLE clients (
 *   id VARCHAR(100) PRIMARY KEY,
 *   issue_date TIMESTAMP NOT NULL,
 *   metadata TEXT NOT NULL,
 *   secret VARCHAR(43),
 *   registration_uri VARCHAR(200),
 *   access_token VARCHAR(43)
 * );
 * </pre>
 *
 * Table name can be customize using {@link #setTableName(String)}.
 *
 * @author Vedran Pavic
 */
public class JdbcClientRepository implements ClientRepository {

	private static final String DEFAULT_TABLE_NAME = "clients";

	private static final String STATEMENT_TEMPLATE_INSERT = "INSERT INTO %s(id, issue_date, metadata, secret, registration_uri, access_token) VALUES (?, ?, ?, ?, ?, ?)";

	private static final String STATEMENT_TEMPLATE_SELECT_BY_ID = "SELECT id, issue_date, metadata, secret, registration_uri, access_token FROM %s WHERE id = ?";

	private static final String STATEMENT_TEMPLATE_SELECT_ALL = "SELECT id, issue_date, metadata, secret, registration_uri, access_token FROM %s";

	private static final String STATEMENT_TEMPLATE_UPDATE = "UPDATE %s SET metadata = ?, secret = ?, access_token = ? WHERE id = ?";

	private static final String STATEMENT_TEMPLATE_DELETE = "DELETE FROM %s WHERE id = ?";

	private static final ClientMapper clientMapper = new ClientMapper();

	private final JdbcOperations jdbcOperations;

	private String tableName = DEFAULT_TABLE_NAME;

	private String statementInsert;

	private String statementSelectById;

	private String statementSelectAll;

	private String statementUpdate;

	private String statementDelete;

	public JdbcClientRepository(JdbcOperations jdbcOperations) {
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");
		this.jdbcOperations = jdbcOperations;
	}

	@PostConstruct
	public void init() {
		prepareStatements();
	}

	@Override
	@Transactional
	public void save(OIDCClientInformation client) {
		Objects.requireNonNull(client, "client must not be null");
		ClientID id = client.getID();
		Date issueDate = client.getIDIssueDate();
		OIDCClientMetadata metadata = client.getOIDCMetadata();
		Secret secret = client.getSecret();
		URI registrationUri = client.getRegistrationURI();
		BearerAccessToken accessToken = client.getRegistrationAccessToken();

		int updatedCount = this.jdbcOperations.update(this.statementUpdate, ps -> {
			ps.setString(1, metadata.toJSONObject().toJSONString());
			ps.setString(2, (secret != null) ? secret.getValue() : null);
			ps.setString(3, (accessToken != null) ? accessToken.getValue() : null);
			ps.setString(4, id.getValue());
		});

		if (updatedCount == 0) {
			this.jdbcOperations.update(this.statementInsert, ps -> {
				ps.setString(1, id.getValue());
				ps.setTimestamp(2, Timestamp.from(issueDate.toInstant()));
				ps.setString(3, metadata.toJSONObject().toJSONString());
				ps.setString(4, (secret != null) ? secret.getValue() : null);
				ps.setString(5, (registrationUri != null) ? registrationUri.toString() : null);
				ps.setString(6, (accessToken != null) ? accessToken.getValue() : null);
			});
		}
	}

	@Override
	@Transactional(readOnly = true)
	public OIDCClientInformation findById(ClientID id) {
		Objects.requireNonNull(id, "id must not be null");
		try {
			return this.jdbcOperations.queryForObject(this.statementSelectById, clientMapper, id.getValue());
		}
		catch (EmptyResultDataAccessException e) {
			return null;
		}
	}

	@Override
	@Transactional(readOnly = true)
	public List<OIDCClientInformation> findAll() {
		return this.jdbcOperations.query(this.statementSelectAll, clientMapper);
	}

	@Override
	@Transactional
	public void deleteById(ClientID id) {
		Objects.requireNonNull(id, "id must not be null");
		this.jdbcOperations.update(this.statementDelete, ps -> ps.setString(1, id.getValue()));
	}

	public void setTableName(String tableName) {
		Objects.requireNonNull(tableName, "tableName must not be null");
		if (StringUtils.isBlank(tableName)) {
			throw new IllegalArgumentException("tableName must not be empty");
		}
		this.tableName = tableName.trim();
	}

	private void prepareStatements() {
		this.statementInsert = String.format(STATEMENT_TEMPLATE_INSERT, this.tableName);
		this.statementSelectById = String.format(STATEMENT_TEMPLATE_SELECT_BY_ID, this.tableName);
		this.statementSelectAll = String.format(STATEMENT_TEMPLATE_SELECT_ALL, this.tableName);
		this.statementUpdate = String.format(STATEMENT_TEMPLATE_UPDATE, this.tableName);
		this.statementDelete = String.format(STATEMENT_TEMPLATE_DELETE, this.tableName);
	}

	private static class ClientMapper implements RowMapper<OIDCClientInformation> {

		@Override
		public OIDCClientInformation mapRow(ResultSet rs, int rowNum) throws SQLException {
			try {
				String id = rs.getString("id");
				Date issueDate = rs.getTimestamp("issue_date");
				String metadata = rs.getString("metadata");
				String secret = rs.getString("secret");
				String registrationUri = rs.getString("registration_uri");
				String accessToken = rs.getString("access_token");

				return new OIDCClientInformation(new ClientID(id), issueDate,
						OIDCClientMetadata.parse(JSONObjectUtils.parse(metadata)),
						(secret != null) ? new Secret(secret) : null,
						(registrationUri != null) ? URI.create(registrationUri) : null,
						(accessToken != null) ? new BearerAccessToken(accessToken) : null);
			}
			catch (ParseException e) {
				throw new TypeMismatchDataAccessException(e.getMessage(), e);
			}
		}

	}

}
