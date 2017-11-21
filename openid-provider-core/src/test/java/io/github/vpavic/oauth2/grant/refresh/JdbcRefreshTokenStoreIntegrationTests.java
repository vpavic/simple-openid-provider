package io.github.vpavic.oauth2.grant.refresh;

import java.time.Instant;

import javax.sql.DataSource;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.jdbc.JdbcTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link JdbcRefreshTokenStore}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@ContextConfiguration
@Transactional
public class JdbcRefreshTokenStoreIntegrationTests {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private JdbcRefreshTokenStore refreshTokenStore;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void save_Valid_ShouldInsert() {
		this.refreshTokenStore.save(new RefreshToken(), RefreshTokenTestUtils.createRefreshTokenContext(null));

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void save_Existing_ShouldThrowException() {
		this.thrown.expect(DuplicateKeyException.class);

		RefreshToken refreshToken = new RefreshToken();
		this.refreshTokenStore.save(refreshToken, RefreshTokenTestUtils.createRefreshTokenContext(null));
		this.refreshTokenStore.save(refreshToken, RefreshTokenTestUtils.createRefreshTokenContext(null));
	}

	@Test
	public void load_Existing_ShouldReturnClient() throws GeneralException {
		RefreshToken refreshToken = new RefreshToken();
		this.refreshTokenStore.save(refreshToken, RefreshTokenTestUtils.createRefreshTokenContext(null));

		assertThat(this.refreshTokenStore.load(refreshToken)).isNotNull();
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void load_Missing_ShouldThrowException() throws GeneralException {
		this.thrown.expect(GeneralException.class);
		this.thrown.expectMessage(OAuth2Error.INVALID_GRANT.getDescription());

		this.refreshTokenStore.load(new RefreshToken());
	}

	@Test
	public void load_Expired_ShouldThrowException() throws GeneralException {
		RefreshToken refreshToken = new RefreshToken();
		this.refreshTokenStore.save(refreshToken,
				RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1)));
		this.thrown.expect(GeneralException.class);
		this.thrown.expectMessage(OAuth2Error.INVALID_GRANT.getDescription());

		this.refreshTokenStore.load(refreshToken);
	}

	@Test
	public void revoke_Existing_ShouldReturnNull() {
		RefreshToken refreshToken = new RefreshToken();
		this.refreshTokenStore.save(refreshToken, RefreshTokenTestUtils.createRefreshTokenContext(null));
		this.refreshTokenStore.revoke(refreshToken);

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Test
	public void revoke_Missing_ShouldReturnNull() {
		this.refreshTokenStore.revoke(new RefreshToken());

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Test
	public void cleanExpiredTokens_Valid_ShouldReturnNull() {
		this.refreshTokenStore.save(new RefreshToken(), RefreshTokenTestUtils.createRefreshTokenContext(null));
		this.refreshTokenStore.cleanExpiredTokens();

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void cleanExpiredTokens_Expired_ShouldReturnNull() {
		this.refreshTokenStore.save(new RefreshToken(),
				RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1)));
		this.refreshTokenStore.cleanExpiredTokens();

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Configuration
	static class Config {

		@Bean
		DataSource dataSource() {
			// @formatter:off
			return new EmbeddedDatabaseBuilder()
					.generateUniqueName(true)
					.setType(EmbeddedDatabaseType.H2)
					.addScript("schema-refresh-tokens.sql")
					.build();
			// @formatter:on
		}

		@Bean
		PlatformTransactionManager transactionManager() {
			return new DataSourceTransactionManager(dataSource());
		}

		@Bean
		JdbcTemplate jdbcTemplate() {
			return new JdbcTemplate(dataSource());
		}

		@Bean
		JdbcRefreshTokenStore refreshTokenStore() {
			return new JdbcRefreshTokenStore(jdbcTemplate());
		}

	}

}
