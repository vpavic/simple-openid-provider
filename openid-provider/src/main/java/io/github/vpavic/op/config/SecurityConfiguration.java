package io.github.vpavic.op.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;

import io.github.vpavic.oauth2.endpoint.AuthorizationEndpoint;
import io.github.vpavic.oauth2.endpoint.EndSessionEndpoint;
import io.github.vpavic.op.login.LoginFormController;

@Configuration
public class SecurityConfiguration {

	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("user").password("{noop}password").roles("USER").build());
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Configuration
	@Order(100)
	static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

		private static final String LOGOUT_URL = "/logout";

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setTargetUrlParameter("continue");

			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(LoginFormController.PATH_MAPPING, LOGOUT_URL, AuthorizationEndpoint.PATH_MAPPING,
							EndSessionEndpoint.PATH_MAPPING)
					.and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.formLogin()
					.loginPage(LoginFormController.PATH_MAPPING)
					.successHandler(successHandler)
					.and()
				.logout()
					.logoutSuccessHandler(new ForwardLogoutSuccessHandler(EndSessionEndpoint.PATH_MAPPING))
					.and()
				.sessionManagement()
					.sessionFixation().migrateSession();
			// @formatter:on
		}

	}

	@Configuration
	@Order(99)
	static class StaticResourcesSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatcher(PathRequest.toStaticResources().atCommonLocations())
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.headers()
					.cacheControl().disable();
			// @formatter:on
		}

	}

}
