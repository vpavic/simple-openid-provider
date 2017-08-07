package io.github.vpavic.op.config;

import java.util.Collections;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import io.github.vpavic.op.key.KeyService;

@Configuration
public class SecurityConfiguration {

	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("user").password("password").roles("USER").build());
		return manager;
	}

	@Order(0)
	@Configuration
	static class EndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers("/oauth2/keys", "/oauth2/token")
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.NEVER)
					.and()
				.authorizeRequests()
					.anyRequest().permitAll();
			// @formatter:on
		}

	}

	@Order(-10)
	@Configuration
	static class LoginSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers("/", "/login", "/logout", "/oauth2/authorize")
					.and()
				.formLogin()
					.permitAll()
					.and()
				.logout()
					.and()
				.authorizeRequests()
					.mvcMatchers("/").permitAll()
					.mvcMatchers("/oauth2/authorize").authenticated();
			// @formatter:on
		}

	}

	@Order(5)
	@Configuration
	static class UserInfoSecurityConfiguration extends WebSecurityConfigurerAdapter {

		private final UserDetailsService userDetailsService;

		private final KeyService keyService;

		UserInfoSecurityConfiguration(ObjectProvider<UserDetailsService> userDetailsService,
				ObjectProvider<KeyService> keyService) {
			this.userDetailsService = userDetailsService.getObject();
			this.keyService = keyService.getObject();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
			authenticationProvider.setPreAuthenticatedUserDetailsService(
					new UserDetailsByNameServiceWrapper<>(this.userDetailsService));

			AuthenticationManager authenticationManager = new ProviderManager(
					Collections.singletonList(authenticationProvider));

			BearerAccessTokenAuthenticationFilter authenticationFilter = new BearerAccessTokenAuthenticationFilter(
					this.keyService, authenticationManager);

			// @formatter:off
			http
				.addFilterBefore(authenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
				.antMatcher("/oauth2/userinfo")
				.cors()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.authorizeRequests()
					.anyRequest().fullyAuthenticated();
			// @formatter:on
		}

	}

}
