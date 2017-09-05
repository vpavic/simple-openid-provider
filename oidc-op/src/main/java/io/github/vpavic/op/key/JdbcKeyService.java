package io.github.vpavic.op.key;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Repository
public class JdbcKeyService implements KeyService {

	private static final String INSERT_STATEMENT = "INSERT INTO keys(content) VALUES (?)";

	private static final String SELECT_ACTIVE_STATEMENT = "SELECT content FROM keys WHERE expiry IS NULL";

	private static final String SELECT_ALL_STATEMENT = "SELECT content FROM keys";

	private static final String UPDATE_EXPIRY_STATEMENT = "UPDATE keys SET expiry = ? WHERE expiry IS NULL";

	private static final String DELETE_EXPIRED_STATEMENT = "DELETE FROM keys WHERE expiry < ?";

	private static final JWKMapper jwkMapper = new JWKMapper();

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	public JdbcKeyService(OpenIdProviderProperties properties, JdbcOperations jdbcOperations) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.properties = properties;
		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional(readOnly = true)
	public JWK findActive() {
		return this.jdbcOperations.queryForObject(SELECT_ACTIVE_STATEMENT, jwkMapper);
	}

	@Override
	@Transactional(readOnly = true)
	public List<JWK> findAll() {
		return this.jdbcOperations.query(SELECT_ALL_STATEMENT, jwkMapper);
	}

	@Override
	@Transactional
	public void rotate() {
		Instant expiry = Instant.now().plus(this.properties.getJwk().getRetentionPeriod(), ChronoUnit.DAYS);

		this.jdbcOperations.update(UPDATE_EXPIRY_STATEMENT, ps -> ps.setTimestamp(1, Timestamp.from(expiry)));

		JWK key = generateKey();
		String content = key.toJSONString();

		this.jdbcOperations.update(INSERT_STATEMENT, content);
	}

	@Scheduled(cron = "0 0 * * * *")
	public void purgeExpiredKeys() {
		Instant now = Instant.now();

		this.jdbcOperations.update(DELETE_EXPIRED_STATEMENT, ps -> ps.setTimestamp(1, Timestamp.from(now)));
	}

	private JWK generateKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			// @formatter:off
			return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
					.privateKey((RSAPrivateKey) keyPair.getPrivate())
					.keyUse(KeyUse.SIGNATURE)
					.algorithm(JWSAlgorithm.RS256)
					.keyID(UUID.randomUUID().toString())
					.build();
			// @formatter:on
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static class JWKMapper implements RowMapper<JWK> {

		@Override
		public JWK mapRow(ResultSet rs, int rowNum) throws SQLException {
			try {
				return JWK.parse(rs.getString(1));
			}
			catch (ParseException e) {
				throw new RuntimeException(e);
			}
		}

	}

}
