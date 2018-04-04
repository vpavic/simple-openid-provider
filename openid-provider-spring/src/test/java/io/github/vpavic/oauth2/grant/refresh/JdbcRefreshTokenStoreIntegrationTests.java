package io.github.vpavic.oauth2.grant.refresh;

import java.time.Instant;
import java.util.UUID;

import javax.sql.DataSource;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.Test;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for {@link JdbcRefreshTokenStore}.
 */
@RunWith(SpringRunner.class)
@ContextConfiguration
@Transactional
public class JdbcRefreshTokenStoreIntegrationTests {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private JdbcRefreshTokenStore refreshTokenStore;

	@Test
	public void save_Valid_ShouldInsert() {
		this.refreshTokenStore.save(RefreshTokenTestUtils.createRefreshTokenContext(null));

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void save_Existing_ShouldThrowException() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		this.refreshTokenStore.save(context);

		assertThatThrownBy(() -> this.refreshTokenStore.save(context)).isInstanceOf(DuplicateKeyException.class);
	}

	@Test
	public void load_Existing_ShouldReturnClient() throws GeneralException {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		this.refreshTokenStore.save(context);

		assertThat(this.refreshTokenStore.load(context.getRefreshToken())).isNotNull();
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void load_Missing_ShouldThrowException() {
		assertThatThrownBy(() -> this.refreshTokenStore.load(new RefreshToken())).isInstanceOf(GeneralException.class)
				.hasMessage(OAuth2Error.INVALID_GRANT.getDescription());
	}

	@Test
	public void load_Expired_ShouldThrowException() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1));
		this.refreshTokenStore.save(context);

		assertThatThrownBy(() -> this.refreshTokenStore.load(context.getRefreshToken()))
				.isInstanceOf(GeneralException.class).hasMessage(OAuth2Error.INVALID_GRANT.getDescription());
	}

	@Test
	public void findByClientIdAndSubject_Existing_ShouldReturnClient() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		this.refreshTokenStore.save(context);

		assertThat(this.refreshTokenStore.findByClientIdAndSubject(context.getClientId(), context.getSubject()))
				.isNotNull();
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void findByClientIdAndSubject_Missing_ShouldReturnNull() {
		assertThat(this.refreshTokenStore.findByClientIdAndSubject(new ClientID(UUID.randomUUID().toString()),
				new Subject(UUID.randomUUID().toString()))).isNull();
	}

	@Test
	public void findByClientIdAndSubject_Expired_ShouldReturnNull() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1));
		this.refreshTokenStore.save(context);

		assertThat(this.refreshTokenStore.findByClientIdAndSubject(context.getClientId(), context.getSubject()))
				.isNull();
	}

	@Test
	public void findBySubject_Existing_ShouldReturnClientList() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		this.refreshTokenStore.save(context);

		assertThat(this.refreshTokenStore.findBySubject(context.getSubject())).hasSize(1);
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void findBySubject_Missing_ShouldReturnEmptyList() {
		assertThat(this.refreshTokenStore.findBySubject(new Subject(UUID.randomUUID().toString()))).isEmpty();
	}

	@Test
	public void findBySubject_Expired_ShouldReturnEmptyList() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1));
		this.refreshTokenStore.save(context);

		assertThat(this.refreshTokenStore.findBySubject(context.getSubject())).isEmpty();
	}

	@Test
	public void revoke_Existing_ShouldReturnNull() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		this.refreshTokenStore.save(context);
		this.refreshTokenStore.revoke(context.getRefreshToken());

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Test
	public void revoke_Missing_ShouldReturnNull() {
		this.refreshTokenStore.revoke(new RefreshToken());

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Test
	public void revokeAllForSubject_Existing_ShouldReturnNull() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		this.refreshTokenStore.save(context);
		this.refreshTokenStore.revokeAllForSubject(context.getSubject());

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Test
	public void revokeAllForSubject_Missing_ShouldReturnNull() {
		this.refreshTokenStore.revokeAllForSubject(new Subject(UUID.randomUUID().toString()));

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(0);
	}

	@Test
	public void cleanExpiredTokens_Valid_ShouldReturnNull() {
		this.refreshTokenStore.save(RefreshTokenTestUtils.createRefreshTokenContext(null));
		this.refreshTokenStore.cleanExpiredTokens();

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "refresh_tokens")).isEqualTo(1);
	}

	@Test
	public void cleanExpiredTokens_Expired_ShouldReturnNull() {
		this.refreshTokenStore.save(RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1)));
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
