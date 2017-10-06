package io.github.vpavic.op.oauth2.jwk;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import io.github.vpavic.op.config.OpenIdProviderProperties;

/**
 * JDBC {@link JwkSetStore} implementation.
 *
 * @author Vedran Pavic
 */
@Repository
public class JdbcJwkSetStore implements JwkSetStore, ApplicationRunner {

	private static final String INSERT_STATEMENT = "INSERT INTO op_jwk_set(jwk_set) VALUES (?)";

	private static final String SELECT_STATEMENT = "SELECT jwk_set FROM op_jwk_set";

	private static final String UPDATE_STATEMENT = "UPDATE op_jwk_set SET jwk_set = ?";

	private static final String EXPIRATIONS_JWK_SET_KEY = "expirations";

	private static final JWKSetMapper jwkSetMapper = new JWKSetMapper();

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	public JdbcJwkSetStore(OpenIdProviderProperties properties, JdbcOperations jdbcOperations) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.properties = properties;
		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional(readOnly = true)
	public JWKSet load() {
		JWKSet jwkSet = doLoad();
		jwkSet.getAdditionalMembers().clear();

		return jwkSet;
	}

	@Override
	@Transactional
	@SuppressWarnings("unchecked")
	public void rotate() {
		JWKSet jwkSet = doLoad();
		List<JWK> rotatingKeys = JwkSetGenerator.generateRotatingKeys();

		List<JWK> keys = new LinkedList<>();
		keys.addAll(rotatingKeys);
		keys.addAll(jwkSet.getKeys());

		Map<String, Object> additionalMembers = jwkSet.getAdditionalMembers();
		Map<Long, List<String>> expirations;

		if (additionalMembers.containsKey(EXPIRATIONS_JWK_SET_KEY)) {
			expirations = (Map<Long, List<String>>) additionalMembers.get(EXPIRATIONS_JWK_SET_KEY);
		}
		else {
			expirations = new HashMap<>();
		}

		long expiration = Instant.now().plusSeconds(this.properties.getJwk().getRetentionPeriod()).toEpochMilli();

		// @formatter:off
		List<String> decommissionedKeyIds = jwkSet.getKeys().stream()
				.limit(rotatingKeys.size())
				.map(JWK::getKeyID)
				.collect(Collectors.toList());
		// @formatter:on

		expirations.put(expiration, decommissionedKeyIds);
		additionalMembers.put(EXPIRATIONS_JWK_SET_KEY, expirations);

		jwkSet = new JWKSet(keys, additionalMembers);
		String jsonString = jwkSet.toJSONObject(false).toJSONString();
		this.jdbcOperations.update(UPDATE_STATEMENT, ps -> ps.setString(1, jsonString));
	}

	@Override
	@Transactional
	public void run(ApplicationArguments args) throws Exception {
		JWKSet jwkSet = doLoad();

		if (jwkSet.getKeys().isEmpty()) {
			List<JWK> keys = new LinkedList<>();
			keys.addAll(JwkSetGenerator.generateRotatingKeys());
			keys.addAll(JwkSetGenerator.generatePermanentKeys());

			jwkSet = new JWKSet(keys);
			String jsonString = jwkSet.toJSONObject(false).toJSONString();
			this.jdbcOperations.update(INSERT_STATEMENT, ps -> ps.setString(1, jsonString));
		}
	}

	@Transactional
	@Scheduled(cron = "0 * * * * *")
	@SuppressWarnings("unchecked")
	public void cleanUpKeys() {
		Instant now = Instant.now();

		JWKSet jwkSet = doLoad();
		Map<String, Object> additionalMembers = jwkSet.getAdditionalMembers();

		if (additionalMembers.containsKey(EXPIRATIONS_JWK_SET_KEY)) {
			Map<String, List<String>> expirations = (Map<String, List<String>>) additionalMembers
					.get(EXPIRATIONS_JWK_SET_KEY);

			// @formatter:off
			Map<Long, List<String>> expiredExpirations = expirations.entrySet().stream()
					.filter(expiration -> now.isAfter(Instant.ofEpochMilli(Long.valueOf(expiration.getKey()))))
					.collect(Collectors.toMap(entry -> Long.valueOf(entry.getKey()), Map.Entry::getValue));
			// @formatter:on

			if (!expiredExpirations.isEmpty()) {
				List<JWK> keys = new LinkedList<>();

				for (JWK key : jwkSet.getKeys()) {
					for (Map.Entry<Long, List<String>> expiredExpiration : expiredExpirations.entrySet()) {
						if (!expiredExpiration.getValue().contains(key.getKeyID())) {
							keys.add(key);
						}
					}
				}

				expiredExpirations.forEach((key, value) -> expirations.remove(key.toString()));

				jwkSet = new JWKSet(keys, Collections.singletonMap(EXPIRATIONS_JWK_SET_KEY, expirations));
				String jsonString = jwkSet.toJSONObject(false).toJSONString();
				this.jdbcOperations.update(UPDATE_STATEMENT, ps -> ps.setString(1, jsonString));
			}
		}
	}

	private JWKSet doLoad() {
		try {
			return this.jdbcOperations.queryForObject(SELECT_STATEMENT, jwkSetMapper);
		}
		catch (EmptyResultDataAccessException e) {
			return new JWKSet();
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
