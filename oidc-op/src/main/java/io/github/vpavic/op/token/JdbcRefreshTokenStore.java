package io.github.vpavic.op.token;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
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
import org.springframework.stereotype.Repository;

@Repository
public class JdbcRefreshTokenStore implements RefreshTokenStore {

	private static final String INSERT_STATEMENT = "INSERT INTO refresh_tokens(token, principal, client_id, scope, expiry) VALUES (?, ?, ?, ?, ?)";

	private static final String SELECT_STATEMENT = "SELECT principal, client_id, scope, expiry FROM refresh_tokens WHERE token = ?";

	private static final String DELETE_STATEMENT = "DELETE FROM refresh_tokens WHERE token = ?";

	private static final String DELETE_EXPIRED_STATEMENT = "DELETE FROM refresh_tokens WHERE expiry < ?";

	private static final RefreshTokenContextMapper refreshTokenContextMapper = new RefreshTokenContextMapper();

	private final JdbcOperations jdbcOperations;

	public JdbcRefreshTokenStore(JdbcOperations jdbcOperations) {
		this.jdbcOperations = Objects.requireNonNull(jdbcOperations);
	}

	@Override
	public void save(RefreshToken refreshToken, RefreshTokenContext context) {
		this.jdbcOperations.update(INSERT_STATEMENT, ps -> {
			ps.setString(1, refreshToken.getValue());
			ps.setString(2, context.getPrincipal().getName());
			ps.setString(3, context.getClientID().getValue());
			ps.setString(4, context.getScope().toString());
			ps.setTimestamp(5, Timestamp.from(context.getExpiry()));
		});
	}

	@Override
	public RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException {
		try {
			RefreshTokenContext context = this.jdbcOperations.queryForObject(SELECT_STATEMENT,
					refreshTokenContextMapper, refreshToken.getValue());

			if (context.isExpired()) {
				throw new GeneralException(OAuth2Error.INVALID_GRANT);
			}

			return context;
		}
		catch (EmptyResultDataAccessException e) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
	}

	@Override
	public void revoke(RefreshToken refreshToken) {
		this.jdbcOperations.update(DELETE_STATEMENT, refreshToken.getValue());
	}

	@Scheduled(cron = "0 0 * * * *")
	public void cleanExpiredTokens() {
		Instant now = Instant.now();
		this.jdbcOperations.update(DELETE_EXPIRED_STATEMENT, now);
	}

	private static class RefreshTokenContextMapper implements RowMapper<RefreshTokenContext> {

		@Override
		public RefreshTokenContext mapRow(ResultSet rs, int rowNum) throws SQLException {
			String principal = rs.getString("principal");
			String clientId = rs.getString("client_id");
			String scope = rs.getString("scope");
			Instant expiry = rs.getTimestamp("expiry").toInstant();

			return new RefreshTokenContext(() -> principal, new ClientID(clientId), Scope.parse(scope), expiry);
		}

	}

}
