package io.github.vpavic.op.oauth2.client;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Configuration
public class ClientRegistrationConfiguration {

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	public ClientRegistrationConfiguration(OpenIdProviderProperties properties,
			ObjectProvider<JdbcOperations> jdbcOperations) {
		this.properties = properties;
		this.jdbcOperations = jdbcOperations.getObject();
	}

	@Bean
	public ClientRepository clientRepository() {
		return new JdbcClientRepository(this.jdbcOperations);
	}

	@Bean
	public ClientService clientService() {
		return new DefaultClientService(this.properties, clientRepository());
	}

	@Bean
	public ClientRegistrationEndpoint clientRegistrationEndpoint() {
		return new ClientRegistrationEndpoint(this.properties, clientService());
	}

	@Bean
	public ClientConfigurationEndpoint clientConfigurationEndpoint() {
		return new ClientConfigurationEndpoint(this.properties, clientRepository(), clientService());
	}

	@Order(94)
	@Configuration
	static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher(ClientRegistrationEndpoint.PATH_MAPPING + "/**")
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

}
