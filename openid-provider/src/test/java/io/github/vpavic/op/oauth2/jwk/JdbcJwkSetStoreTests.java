package io.github.vpavic.op.oauth2.jwk;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.test.context.junit4.SpringRunner;

import io.github.vpavic.op.config.OpenIdProviderConfiguration;
import io.github.vpavic.op.config.OpenIdProviderProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JdbcJwkSetStore}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@JdbcTest
@Import(OpenIdProviderConfiguration.class)
public class JdbcJwkSetStoreTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private OpenIdProviderProperties properties;

	@Autowired
	private JdbcOperations jdbcOperations;

	private JdbcJwkSetStore jwkSetStore;

	@Before
	public void setUp() throws Exception {
		this.jwkSetStore = new JdbcJwkSetStore(this.properties, this.jdbcOperations);
		this.jwkSetStore.run(null);
	}

	@Test
	public void load() {
		JWKSet keys = this.jwkSetStore.load();
		assertThat(keys.getKeys().size()).isEqualTo(7);
	}

	@Test
	public void rotate() throws Exception {
		this.jwkSetStore.rotate();

		JWKSet keys = this.jwkSetStore.load();
		assertThat(keys.getKeys().size()).isEqualTo(12);
	}

	@Test
	public void cleanUp() throws Exception {
		this.properties.getJwk().setRetentionPeriod(1);
		this.jwkSetStore.cleanUp();

		JWKSet keys = this.jwkSetStore.load();
		assertThat(keys.getKeys().size()).isEqualTo(7);

		this.jwkSetStore.rotate();
		this.jwkSetStore.cleanUp();

		keys = this.jwkSetStore.load();
		assertThat(keys.getKeys().size()).isEqualTo(12);

		Thread.sleep(1000);
		this.jwkSetStore.cleanUp();

		keys = this.jwkSetStore.load();
		assertThat(keys.getKeys().size()).isEqualTo(7);
	}

}
