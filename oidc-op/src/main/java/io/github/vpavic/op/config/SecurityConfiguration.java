package io.github.vpavic.op.config;

import java.util.Collections;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.endpoint.AuthorizationEndpoint;
import io.github.vpavic.op.endpoint.CheckSessionIframe;
import io.github.vpavic.op.endpoint.DiscoveryEndpoint;
import io.github.vpavic.op.endpoint.KeysEndpoint;
import io.github.vpavic.op.endpoint.LoginEndpoint;
import io.github.vpavic.op.endpoint.LogoutEndpoint;
import io.github.vpavic.op.endpoint.TokenEndpoint;
import io.github.vpavic.op.endpoint.UserInfoEndpoint;
import io.github.vpavic.op.key.KeyService;
import io.github.vpavic.op.security.web.authentication.BearerAccessTokenAuthenticationFilter;
import io.github.vpavic.op.security.web.authentication.OpenIdWebAuthenticationDetails;
import io.github.vpavic.op.security.web.authentication.logout.OpenIdLogoutSuccessHandler;

@Configuration
public class SecurityConfiguration {

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
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.NEVER);
			// @formatter:on
		}

	}

	@Order(-15)
	@Configuration
	@ConditionalOnProperty(prefix = "oidc.op", name = "session-management-enabled", havingValue = "true")
	static class CheckSessionConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher(CheckSessionIframe.PATH_MAPPING)
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.headers()
					.frameOptions().disable();
			// @formatter:on
		}

	}

	@Order(-10)
	@Configuration
	static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

		private final OpenIdProviderProperties properties;

		private final ClientRepository clientRepository;

		public WebSecurityConfiguration(OpenIdProviderProperties properties,
				ObjectProvider<ClientRepository> clientRepository) {
			this.properties = properties;
			this.clientRepository = clientRepository.getObject();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setTargetUrlParameter("continue");

			// @formatter:off
			http
				.requestMatchers()
					.antMatchers("/", LoginEndpoint.PATH_MAPPING, LogoutEndpoint.PATH_MAPPING,
							AuthorizationEndpoint.PATH_MAPPING, "/web/**")
					.and()
				.authorizeRequests()
					.antMatchers("/", LoginEndpoint.PATH_MAPPING, AuthorizationEndpoint.PATH_MAPPING).permitAll()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.loginPage(LoginEndpoint.PATH_MAPPING)
					.authenticationDetailsSource(OpenIdWebAuthenticationDetails::new)
					.successHandler(successHandler)
					.and()
				.logout().logoutSuccessHandler(
						new OpenIdLogoutSuccessHandler(this.properties, this.clientRepository));
			// @formatter:on
		}

	}

	@Order(5)
	@Configuration
	static class UserInfoSecurityConfiguration extends WebSecurityConfigurerAdapter {

		private final OpenIdProviderProperties properties;

		private final UserDetailsService userDetailsService;

		private final KeyService keyService;

		UserInfoSecurityConfiguration(OpenIdProviderProperties properties,
				ObjectProvider<UserDetailsService> userDetailsService, ObjectProvider<KeyService> keyService) {
			this.properties = properties;
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
					this.properties.getIssuer(), this.keyService, authenticationManager);

			// @formatter:off
			http
				.antMatcher(UserInfoEndpoint.PATH_MAPPING)
				.authorizeRequests()
					.anyRequest().fullyAuthenticated()
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

}
