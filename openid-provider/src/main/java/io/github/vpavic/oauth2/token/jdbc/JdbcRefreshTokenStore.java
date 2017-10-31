package io.github.vpavic.oauth2.token.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import io.github.vpavic.oauth2.token.RefreshTokenContext;
import io.github.vpavic.oauth2.token.RefreshTokenStore;

public class JdbcRefreshTokenStore implements RefreshTokenStore {

	private static final String INSERT_STATEMENT = "INSERT INTO op_refresh_tokens(token, principal, client_id, scope, expiry) VALUES (?, ?, ?, ?, ?)";

	private static final String SELECT_STATEMENT = "SELECT principal, client_id, scope, expiry FROM op_refresh_tokens WHERE token = ?";

	private static final String DELETE_STATEMENT = "DELETE FROM op_refresh_tokens WHERE token = ?";

	private static final String DELETE_EXPIRED_STATEMENT = "DELETE FROM op_refresh_tokens WHERE expiry > 0 AND expiry < ?";

	private static final RefreshTokenContextMapper refreshTokenContextMapper = new RefreshTokenContextMapper();

	private final JdbcOperations jdbcOperations;

	public JdbcRefreshTokenStore(JdbcOperations jdbcOperations) {
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional
	public void save(RefreshToken refreshToken, RefreshTokenContext context) {
		Instant expiry = context.getExpiry();

		this.jdbcOperations.update(INSERT_STATEMENT, ps -> {
			ps.setString(1, refreshToken.getValue());
			ps.setString(2, context.getPrincipal());
			ps.setString(3, context.getClientId().getValue());
			ps.setString(4, context.getScope().toString());
			ps.setLong(5, (expiry != null) ? expiry.getEpochSecond() : 0);
		});
	}

	@Override
	@Transactional(readOnly = true)
	public RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException {
		try {
			RefreshTokenContext context = this.jdbcOperations.queryForObject(SELECT_STATEMENT,
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
		this.jdbcOperations.update(DELETE_STATEMENT, ps -> ps.setString(1, refreshToken.getValue()));
	}

	@Scheduled(cron = "0 0 * * * *")
	public void cleanExpiredTokens() {
		Instant now = Instant.now();

		this.jdbcOperations.update(DELETE_EXPIRED_STATEMENT, ps -> ps.setLong(1, now.getEpochSecond()));
	}

	private static class RefreshTokenContextMapper implements RowMapper<RefreshTokenContext> {

		@Override
		public RefreshTokenContext mapRow(ResultSet rs, int rowNum) throws SQLException {
			String principal = rs.getString(1);
			String clientId = rs.getString(2);
			String scope = rs.getString(3);
			long expiry = rs.getLong(4);

			return new RefreshTokenContext(principal, new ClientID(clientId), Scope.parse(scope),
					expiry > 0 ? Instant.ofEpochSecond(expiry) : null);
		}

	}

}
