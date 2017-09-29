package io.github.vpavic.op.oauth2.jwk;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class JdbcJwkSetStore implements JwkSetStore {

	private static final String INSERT_STATEMENT = "INSERT INTO op_jwk_set(jwk_set) VALUES (?)";

	private static final String SELECT_STATEMENT = "SELECT jwk_set FROM op_jwk_set";

	private static final String UPDATE_STATEMENT = "UPDATE op_jwk_set SET jwk_set = ?";

	private static final JWKSetMapper jwkSetMapper = new JWKSetMapper();

	private final JdbcOperations jdbcOperations;

	public JdbcJwkSetStore(JdbcOperations jdbcOperations) {
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional(readOnly = true)
	public JWKSet load() {
		try {
			return this.jdbcOperations.queryForObject(SELECT_STATEMENT, jwkSetMapper);
		}
		catch (EmptyResultDataAccessException e) {
			return new JWKSet();
		}
	}

	@Override
	@Transactional
	public void save(JWKSet jwkSet) {
		if (load().getKeys().isEmpty()) {
			this.jdbcOperations.update(INSERT_STATEMENT, ps -> ps.setString(1, jwkSet.toJSONObject(false).toJSONString()));
		}
		else {
			this.jdbcOperations.update(UPDATE_STATEMENT, ps -> ps.setString(1, jwkSet.toJSONObject(false).toJSONString()));
		}
	}

	private static class JWKSetMapper implements RowMapper<JWKSet> {

		@Override
		public JWKSet mapRow(ResultSet rs, int rowNum) throws SQLException {
			try {
				return JWKSet.parse(rs.getString(1));
			}
			catch (ParseException e) {
				throw new DataRetrievalFailureException(e.getMessage(), e);
			}
		}

	}

}
