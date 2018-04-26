package io.github.vpavic.oauth2.grant.refresh;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.annotation.PostConstruct;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import io.github.vpavic.oauth2.util.StringUtils;

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
 */
public class JdbcRefreshTokenStore implements RefreshTokenStore {

	private static final String DEFAULT_TABLE_NAME = "refresh_tokens";

	private static final String STATEMENT_TEMPLATE_INSERT = "INSERT INTO %s(token, client_id, subject, scope, expiry) VALUES (?, ?, ?, ?, ?)";

	private static final String STATEMENT_TEMPLATE_SELECT_BY_TOKEN = "SELECT token, client_id, subject, scope, expiry FROM %s WHERE token = ?";

	private static final String STATEMENT_TEMPLATE_SELECT_BY_CLIENT_AND_SUBJECT = "SELECT token, client_id, subject, scope, expiry FROM %s WHERE client_id = ? AND subject = ?";

	private static final String STATEMENT_TEMPLATE_SELECT_BY_SUBJECT = "SELECT token, client_id, subject, scope, expiry FROM %s WHERE subject = ?";

	private static final String STATEMENT_TEMPLATE_DELETE_BY_TOKEN = "DELETE FROM %s WHERE token = ?";

	private static final String STATEMENT_TEMPLATE_DELETE_BY_SUBJECT = "DELETE FROM %s WHERE subject = ?";

	private static final String STATEMENT_TEMPLATE_DELETE_EXPIRED = "DELETE FROM %s WHERE expiry > 0 AND expiry < ?";

	private static final RefreshTokenContextMapper refreshTokenContextMapper = new RefreshTokenContextMapper();

	private final JdbcOperations jdbcOperations;

	private String tableName = DEFAULT_TABLE_NAME;

	private String statementInsert;

	private String statementSelectByToken;

	private String statementSelectByClientIdAndSubject;

	private String statementSelectBySubject;

	private String statementDeleteByToken;

	private String statementDeleteBySubject;

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
	public void save(RefreshTokenContext context) {
		Objects.requireNonNull(context, "context must not be null");
		Instant expiry = context.getExpiry();
		this.jdbcOperations.update(this.statementInsert, ps -> {
			ps.setString(1, context.getRefreshToken().getValue());
			ps.setString(2, context.getClientId().getValue());
			ps.setString(3, context.getSubject().getValue());
			ps.setString(4, context.getScope().toString());
			ps.setLong(5, (expiry != null) ? expiry.getEpochSecond() : 0);
		});
	}

	@Override
	@Transactional(readOnly = true)
	public RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		try {
			RefreshTokenContext context = this.jdbcOperations.queryForObject(this.statementSelectByToken,
					refreshTokenContextMapper, refreshToken.getValue());
			if (context.isExpired()) {
				this.jdbcOperations.update(this.statementDeleteByToken, ps -> ps.setString(1, refreshToken.getValue()));
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
	public RefreshTokenContext findByClientIdAndSubject(ClientID clientId, Subject subject) {
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(subject, "subject must not be null");
		try {
			RefreshTokenContext context = this.jdbcOperations.queryForObject(this.statementSelectByClientIdAndSubject,
					refreshTokenContextMapper, clientId.getValue(), subject.getValue());
			if (context.isExpired()) {
				this.jdbcOperations.update(this.statementDeleteByToken,
						ps -> ps.setString(1, context.getRefreshToken().getValue()));
				return null;
			}
			return context;
		}
		catch (EmptyResultDataAccessException e) {
			return null;
		}
	}

	@Override
	@Transactional
	public List<RefreshTokenContext> findBySubject(Subject subject) {
		Objects.requireNonNull(subject, "subject must not be null");
		List<RefreshTokenContext> results = new ArrayList<>();
		List<RefreshTokenContext> contexts = this.jdbcOperations.query(this.statementSelectBySubject,
				refreshTokenContextMapper, subject.getValue());
		for (RefreshTokenContext context : contexts) {
			if (context.isExpired()) {
				this.jdbcOperations.update(this.statementDeleteByToken,
						ps -> ps.setString(1, context.getRefreshToken().getValue()));
			}
			else {
				results.add(context);
			}
		}
		return results;
	}

	@Override
	@Transactional
	public void revoke(RefreshToken refreshToken) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		this.jdbcOperations.update(this.statementDeleteByToken, ps -> ps.setString(1, refreshToken.getValue()));
	}

	@Override
	public void revokeAllForSubject(Subject subject) {
		Objects.requireNonNull(subject, "subject must not be null");
		this.jdbcOperations.update(this.statementDeleteBySubject, subject.getValue());
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
		this.statementSelectByToken = String.format(STATEMENT_TEMPLATE_SELECT_BY_TOKEN, this.tableName);
		this.statementSelectByClientIdAndSubject = String.format(STATEMENT_TEMPLATE_SELECT_BY_CLIENT_AND_SUBJECT,
				this.tableName);
		this.statementSelectBySubject = String.format(STATEMENT_TEMPLATE_SELECT_BY_SUBJECT, this.tableName);
		this.statementDeleteByToken = String.format(STATEMENT_TEMPLATE_DELETE_BY_TOKEN, this.tableName);
		this.statementDeleteBySubject = String.format(STATEMENT_TEMPLATE_DELETE_BY_SUBJECT, this.tableName);
		this.statementDeleteExpired = String.format(STATEMENT_TEMPLATE_DELETE_EXPIRED, this.tableName);
	}

	private static class RefreshTokenContextMapper implements RowMapper<RefreshTokenContext> {

		@Override
		public RefreshTokenContext mapRow(ResultSet rs, int rowNum) throws SQLException {
			String refreshToken = rs.getString("token");
			String clientId = rs.getString("client_id");
			String subject = rs.getString("subject");
			String scope = rs.getString("scope");
			long expiry = rs.getLong("expiry");

			return new RefreshTokenContext(new RefreshToken(refreshToken), new ClientID(clientId), new Subject(subject),
					Scope.parse(scope), expiry > 0 ? Instant.ofEpochSecond(expiry) : null);
		}

	}

}
