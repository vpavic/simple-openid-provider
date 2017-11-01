package io.github.vpavic.oauth2;

import java.util.Collections;

import com.nimbusds.oauth2.sdk.id.Issuer;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.userinfo.BearerAccessTokenAuthenticationFilter;
import io.github.vpavic.oauth2.userinfo.UserInfoEndpoint;

@Order(-1)
@Configuration
public class UserInfoSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	UserInfoSecurityConfiguration(UserDetailsService userDetailsService, Issuer issuer, JwkSetLoader jwkSetLoader) {
		this.userDetailsService = userDetailsService;
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
		authenticationProvider
				.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<>(this.userDetailsService));

		AuthenticationManager authenticationManager = new ProviderManager(
				Collections.singletonList(authenticationProvider));

		BearerAccessTokenAuthenticationFilter authenticationFilter = new BearerAccessTokenAuthenticationFilter(
				this.issuer, this.jwkSetLoader, authenticationManager);

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
			.addFilterBefore(authenticationFilter, AbstractPreAuthenticatedProcessingFilter.class);
		// @formatter:on
	}

}
