package io.github.vpavic.oauth2.jwk;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class JwkSetConfiguration {

	private final JwkSetLoader jwkSetLoader;

	public JwkSetConfiguration(ObjectProvider<JwkSetLoader> jwkSetLoader) {
		this.jwkSetLoader = jwkSetLoader.getObject();
	}

	@Bean
	public JwkSetEndpoint jwkSetEndpoint() {
		return new JwkSetEndpoint(this.jwkSetLoader);
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
