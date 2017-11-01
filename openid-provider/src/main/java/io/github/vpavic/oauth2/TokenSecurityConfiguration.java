package io.github.vpavic.oauth2;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.token.TokenEndpoint;
import io.github.vpavic.oauth2.token.TokenRevocationEndpoint;

@Order(0)
@Configuration
public class TokenSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.requestMatchers()
				.antMatchers(HttpMethod.POST, TokenEndpoint.PATH_MAPPING, TokenRevocationEndpoint.PATH_MAPPING)
				.and()
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
