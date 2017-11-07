package io.github.vpavic.oauth2;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.endpoint.CheckSessionIframe;

@Order(-3)
@Configuration
public class LogoutSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.requestMatchers()
				.antMatchers(HttpMethod.GET, CheckSessionIframe.PATH_MAPPING)
				.and()
			.authorizeRequests()
				.anyRequest().permitAll()
				.and()
			.headers()
				.cacheControl().disable()
				.frameOptions().disable()
				.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		// @formatter:on
	}

}
