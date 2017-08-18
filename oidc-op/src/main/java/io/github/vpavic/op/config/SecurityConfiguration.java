package io.github.vpavic.op.config;

import java.util.Collections;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import io.github.vpavic.op.endpoint.AuthorizationEndpoint;
import io.github.vpavic.op.endpoint.CheckSessionEndpoint;
import io.github.vpavic.op.endpoint.DiscoveryEndpoint;
import io.github.vpavic.op.endpoint.KeysEndpoint;
import io.github.vpavic.op.endpoint.TokenEndpoint;
import io.github.vpavic.op.endpoint.UserInfoEndpoint;
import io.github.vpavic.op.key.KeyService;

@Configuration
public class SecurityConfiguration {

	static final String LOGIN_URL = "/login";

	static final String LOGOUT_URL = "/logout";

	@Bean
	public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
		JdbcDaoImpl userDetailsService = new JdbcDaoImpl();
		userDetailsService.setJdbcTemplate(jdbcTemplate);
		return userDetailsService;
	}

	@Order(0)
	@Configuration
	static class EndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(KeysEndpoint.PATH_MAPPING, TokenEndpoint.PATH_MAPPING, DiscoveryEndpoint.PATH_MAPPING)
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

	@Order(-15)
	@Configuration
	static class CheckSessionConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher(CheckSessionEndpoint.PATH_MAPPING)
				.headers()
					.frameOptions().disable()
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
					.antMatchers("/", LOGIN_URL, LOGOUT_URL, AuthorizationEndpoint.PATH_MAPPING)
					.and()
				.authorizeRequests()
					.antMatchers(LOGIN_URL).permitAll()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.loginPage(LOGIN_URL)
					.and()
				.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher(LOGOUT_URL, HttpMethod.GET.name()))
					.logoutSuccessHandler(logoutSuccessHandler());
			// @formatter:on
		}

		private LogoutSuccessHandler logoutSuccessHandler() {
			SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
			logoutSuccessHandler.setDefaultTargetUrl(LOGIN_URL + "?logout");
			logoutSuccessHandler.setTargetUrlParameter("post_logout_redirect_uri");
			return logoutSuccessHandler;
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
				.antMatcher(UserInfoEndpoint.PATH_MAPPING)
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
