package io.github.vpavic.oauth2.grant.refresh;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Objects;

import javax.annotation.PostConstruct;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

/**
 * A JDBC implementation of {@link RefreshTokenStore}.
 *
 * By default uses table named {@code refresh_tokens} with the following definition:
 *
 * <pre class="code">
 * CREATE TABLE refresh_tokens (
 *   token VARCHAR(43) PRIMARY KEY,
 *   subject VARCHAR(30) NOT NULL,
 *   client_id VARCHAR(100) NOT NULL,
 *   scope VARCHAR(200) NOT NULL,
 *   expiry BIGINT NOT NULL
 * );
 * </pre>
 *
 * Table name can be customize using {@link #setTableName(String)}.
 *
 * @author Vedran Pavic
 */
public class JdbcRefreshTokenStore implements RefreshTokenStore {

	private static final String DEFAULT_TABLE_NAME = "refresh_tokens";

	private static final String STATEMENT_TEMPLATE_INSERT = "INSERT INTO %s(token, subject, client_id, scope, expiry) VALUES (?, ?, ?, ?, ?)";

	private static final String STATEMENT_TEMPLATE_SELECT = "SELECT subject, client_id, scope, expiry FROM %s WHERE token = ?";

	private static final String STATEMENT_TEMPLATE_DELETE = "DELETE FROM %s WHERE token = ?";

	private static final String STATEMENT_TEMPLATE_DELETE_EXPIRED = "DELETE FROM %s WHERE expiry > 0 AND expiry < ?";

	private static final RefreshTokenContextMapper refreshTokenContextMapper = new RefreshTokenContextMapper();

	private final JdbcOperations jdbcOperations;

	private String tableName = DEFAULT_TABLE_NAME;

	private String statementInsert;

	private String statementSelect;

	private String statementDelete;

	private String statementDeleteExpired;

	public JdbcRefreshTokenStore(JdbcOperations jdbcOperations) {
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");
		this.jdbcOperations = jdbcOperations;
	}

	@PostConstruct
	public void init() {
		prepareStatements();
	}

	@Override
	@Transactional
	public void save(RefreshToken refreshToken, RefreshTokenContext context) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		Objects.requireNonNull(context, "context must not be null");
		Instant expiry = context.getExpiry();
		this.jdbcOperations.update(this.statementInsert, ps -> {
			ps.setString(1, refreshToken.getValue());
			ps.setString(2, context.getSubject().getValue());
			ps.setString(3, context.getClientId().getValue());
			ps.setString(4, context.getScope().toString());
			ps.setLong(5, (expiry != null) ? expiry.getEpochSecond() : 0);
		});
	}

	@Override
	@Transactional(readOnly = true)
	public RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		try {
			RefreshTokenContext context = this.jdbcOperations.queryForObject(this.statementSelect,
					refreshTokenContextMapper, refreshToken.getValue());
			if (context == null || context.isExpired()) {
				throw new GeneralException(OAuth2Error.INVALID_GRANT);
			}
			return context;
		}
		catch (EmptyResultDataAccessException e) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
	}

	@Override
	@Transactional
	public void revoke(RefreshToken refreshToken) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		this.jdbcOperations.update(this.statementDelete, ps -> ps.setString(1, refreshToken.getValue()));
	}

	@Scheduled(cron = "0 0 * * * *")
	public void cleanExpiredTokens() {
		this.jdbcOperations.update(this.statementDeleteExpired, ps -> ps.setLong(1, Instant.now().getEpochSecond()));
	}

	public void setTableName(String tableName) {
		Objects.requireNonNull(tableName, "tableName must not be null");
		if (StringUtils.isBlank(tableName)) {
			throw new IllegalArgumentException("tableName must not be empty");
		}
		this.tableName = tableName;
	}

	private void prepareStatements() {
		this.statementInsert = String.format(STATEMENT_TEMPLATE_INSERT, this.tableName);
		this.statementSelect = String.format(STATEMENT_TEMPLATE_SELECT, this.tableName);
		this.statementDelete = String.format(STATEMENT_TEMPLATE_DELETE, this.tableName);
		this.statementDeleteExpired = String.format(STATEMENT_TEMPLATE_DELETE_EXPIRED, this.tableName);
	}

	private static class RefreshTokenContextMapper implements RowMapper<RefreshTokenContext> {

		@Override
		public RefreshTokenContext mapRow(ResultSet rs, int rowNum) throws SQLException {
			String subject = rs.getString("subject");
			String clientId = rs.getString("client_id");
			String scope = rs.getString("scope");
			long expiry = rs.getLong("expiry");

			return new RefreshTokenContext(new Subject(subject), new ClientID(clientId), Scope.parse(scope),
					expiry > 0 ? Instant.ofEpochSecond(expiry) : null);
		}

	}

}
