package io.github.vpavic.oauth2.jwk;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import io.github.vpavic.oauth2.OpenIdProviderProperties;

/**
 * JDBC {@link JwkSetStore} implementation.
 *
 * @author Vedran Pavic
 */
public class JdbcJwkSetStore implements JwkSetStore, ApplicationRunner {

	private static final String INSERT_STATEMENT = "INSERT INTO op_keys(jwk, expiry) VALUES (?, ?)";

	private static final String SELECT_STATEMENT = "SELECT jwk FROM op_keys ORDER BY id DESC";

	private static final String UPDATE_STATEMENT = "UPDATE op_keys SET expiry = ? WHERE expiry IS NULL";

	private static final String DELETE_STATEMENT = "DELETE FROM op_keys WHERE expiry < ?";

	private static final Instant permanentKeyExpiry = Instant.ofEpochSecond(253402300799L);

	private static final JwkMapper jwkMapper = new JwkMapper();

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	/**
	 * Create a new {@link JdbcJwkSetStore} instance.
	 * @param properties the OpenID Provider properties
	 * @param jdbcOperations the {@link JdbcOperations} to use
	 */
	public JdbcJwkSetStore(OpenIdProviderProperties properties, JdbcOperations jdbcOperations) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.properties = properties;
		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional(readOnly = true)
	public JWKSet load() {
		List<JWK> keys = loadKeys();

		return new JWKSet(keys);
	}

	@Override
	@Transactional
	public void rotate() {
		Instant expiration = Instant.now().plusSeconds(this.properties.getJwk().getRetentionPeriod());
		this.jdbcOperations.update(UPDATE_STATEMENT, ps -> ps.setTimestamp(1, Timestamp.from(expiration)));
		generateAndSaveRotatingKeys();
	}

	@Override
	@Transactional
	public void run(ApplicationArguments args) throws Exception {
		List<JWK> keys = loadKeys();

		if (keys.isEmpty()) {
			generateAndSavePermanentKeys();
			generateAndSaveRotatingKeys();
		}
	}

	@Transactional
	@Scheduled(cron = "0 * * * * *")
	public void cleanUp() {
		Instant now = Instant.now();
		this.jdbcOperations.update(DELETE_STATEMENT, ps -> ps.setTimestamp(1, Timestamp.from(now)));
	}

	private List<JWK> loadKeys() {
		return this.jdbcOperations.query(SELECT_STATEMENT, jwkMapper);
	}

	private void generateAndSaveRotatingKeys() {
		List<JWK> keys = new LinkedList<>();
		keys.add(JwkGenerator.generateEncryptionAesKey());
		keys.add(JwkGenerator.generateSigningEcKey(Curve.P_521));
		keys.add(JwkGenerator.generateSigningEcKey(Curve.P_384));
		keys.add(JwkGenerator.generateSigningEcKey(Curve.P_256));
		keys.add(JwkGenerator.generateSigningRsaKey());
		keys.forEach(key -> save(key, null));
	}

	private void generateAndSavePermanentKeys() {
		List<JWK> keys = new LinkedList<>();
		keys.add(JwkGenerator.generateSubjectEncryptionAesKey());
		keys.add(JwkGenerator.generateSigningHmacSha256Key());
		keys.forEach(key -> save(key, permanentKeyExpiry));
	}

	private void save(JWK key, Instant expiry) {
		String jsonString = key.toJSONString();
		this.jdbcOperations.update(INSERT_STATEMENT, ps -> {
			ps.setString(1, jsonString);
			ps.setTimestamp(2, (expiry != null) ? Timestamp.from(expiry) : null);
		});
	}

	private static class JwkMapper implements RowMapper<JWK> {

		@Override
		public JWK mapRow(ResultSet rs, int rowNum) throws SQLException {
			try {
				return JWK.parse(rs.getString(1));
			}
			catch (ParseException e) {
				throw new DataRetrievalFailureException(e.getMessage(), e);
			}
		}

	}

}
