package io.github.vpavic.oauth2;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.client.ClientRegistrationEndpoint;

@Order(-2)
@Configuration
public class ClientRegistrationSecurityConfiguration extends WebSecurityConfigurerAdapter {

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
