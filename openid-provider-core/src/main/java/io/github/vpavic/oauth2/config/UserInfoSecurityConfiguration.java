package io.github.vpavic.oauth2.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import io.github.vpavic.oauth2.authentication.BearerTokenAuthenticationProcessingFilter;
import io.github.vpavic.oauth2.authentication.BearerTokenAuthenticationResolver;
import io.github.vpavic.oauth2.endpoint.UserInfoEndpoint;

@Order(-1)
@Configuration
public class UserInfoSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final BearerTokenAuthenticationResolver authenticationResolver;

	public UserInfoSecurityConfiguration(ObjectProvider<BearerTokenAuthenticationResolver> authenticationResolver) {
		this.authenticationResolver = authenticationResolver.getObject();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.antMatcher(UserInfoEndpoint.PATH_MAPPING)
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.cors()
				.and()
			.csrf()
				.disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			.addFilterBefore(new BearerTokenAuthenticationProcessingFilter(this.authenticationResolver), AbstractPreAuthenticatedProcessingFilter.class);
		// @formatter:on
	}

}
