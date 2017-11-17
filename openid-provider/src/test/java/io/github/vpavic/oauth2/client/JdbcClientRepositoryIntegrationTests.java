package io.github.vpavic.oauth2.client;

import javax.sql.DataSource;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
 * Integration tests for {@link JdbcClientRepository}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@ContextConfiguration
@Transactional
public class JdbcClientRepositoryIntegrationTests {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private JdbcClientRepository clientRepository;

	@Test
	public void save_New_ShouldInsert() {
		this.clientRepository.save(ClientTestUtils.createClient());

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(1);
	}

	@Test
	public void save_Existing_ShouldUpdate() {
		OIDCClientInformation client = ClientTestUtils.createClient();
		this.clientRepository.save(client);
		client = new OIDCClientInformation(client.getID(), client.getIDIssueDate(), client.getOIDCMetadata(),
				new Secret(), client.getRegistrationURI(), new BearerAccessToken());
		this.clientRepository.save(client);

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(1);
	}

	@Test
	public void findById_Existing_ShouldReturnClient() {
		OIDCClientInformation client = ClientTestUtils.createClient();
		this.clientRepository.save(client);

		assertThat(this.clientRepository.findById(client.getID())).isNotNull();
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(1);
	}

	@Test
	public void findById_Missing_ShouldReturnNull() {
		assertThat(this.clientRepository.findById(new ClientID())).isNull();
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(0);
	}

	@Test
	public void findAll_Na_ShouldReturnClients() {
		this.clientRepository.save(ClientTestUtils.createClient());
		this.clientRepository.save(ClientTestUtils.createClient());

		assertThat(this.clientRepository.findAll()).hasSize(2);
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(2);
	}

	@Test
	public void findAll_Na_ShouldReturnEmptyList() {
		assertThat(this.clientRepository.findAll()).hasSize(0);
		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(0);
	}

	@Test
	public void deleteById_Valid_ShouldReturnNull() {
		OIDCClientInformation client = ClientTestUtils.createClient();
		this.clientRepository.save(client);
		this.clientRepository.deleteById(client.getID());

		assertThat(JdbcTestUtils.countRowsInTable(this.jdbcTemplate, "clients")).isEqualTo(0);
	}

	@Configuration
	static class Config {

		@Bean
		DataSource dataSource() {
			// @formatter:off
			return new EmbeddedDatabaseBuilder()
					.generateUniqueName(true)
					.setType(EmbeddedDatabaseType.H2)
					.addScript("schema-clients.sql")
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
		JdbcClientRepository clientRepository() {
			return new JdbcClientRepository(jdbcTemplate());
		}

	}

}
