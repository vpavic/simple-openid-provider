package io.github.vpavic.op.oauth2.jwk;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Configuration
public class JwkSetConfiguration {

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	public JwkSetConfiguration(OpenIdProviderProperties properties, ObjectProvider<JdbcOperations> jdbcOperations) {
		this.properties = properties;
		this.jdbcOperations = jdbcOperations.getObject();
	}

	@Bean
	public JwkSetStore jwkSetStore() {
		return new JdbcJwkSetStore(this.properties, this.jdbcOperations);
	}

	@Bean
	public JwkSetEndpoint jwkSetEndpoint() {
		return new JwkSetEndpoint(jwkSetStore());
	}

	@Order(93)
	@Configuration
	static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher(JwkSetEndpoint.PATH_MAPPING)
				.authorizeRequests()
					.anyRequest().permitAll();
			// @formatter:on
		}

	}

}
