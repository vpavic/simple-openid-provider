package io.github.vpavic.op.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.autoconfigure.security.EndpointRequest;
import org.springframework.boot.autoconfigure.security.StaticResourceRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;

import io.github.vpavic.op.interfaces.login.LoginFormController;
import io.github.vpavic.op.oauth2.authorization.AuthorizationEndpoint;
import io.github.vpavic.op.oauth2.endsession.EndSessionEndpoint;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);

	private final SecurityProperties properties;

	public SecurityConfiguration(SecurityProperties properties) {
		this.properties = properties;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		SecurityProperties.User userProperties = this.properties.getUser();

		if (userProperties.isDefaultPassword()) {
			logger.info(String.format("Using default security password:%n%n%s%n", userProperties.getPassword()));
		}

		// @formatter:off
		UserDetails user = User.withUsername(userProperties.getName())
				.password(userProperties.getPassword())
				.roles("USER")
				.build();
		// @formatter:on

		InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
		userDetailsManager.createUser(user);

		return userDetailsManager;
	}

	@Order(100)
	@Configuration
	static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setTargetUrlParameter("continue");

			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/", LoginFormController.PATH_MAPPING, AuthorizationEndpoint.PATH_MAPPING,
							EndSessionEndpoint.PATH_MAPPING)
						.permitAll()
					.antMatchers("/web/**").hasRole("USER")
					.anyRequest().denyAll()
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

	@Order(99)
	@Configuration
	static class StaticResourcesSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatcher(StaticResourceRequest.toCommonLocations())
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.headers()
					.cacheControl().disable();
			// @formatter:on
		}

	}

	@Order(98)
	@Configuration
	static class ActuatorSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatcher(EndpointRequest.toAnyEndpoint())
				.authorizeRequests()
					.requestMatchers(EndpointRequest.to("status", "info")).permitAll()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.NEVER);
			// @formatter:on
		}

	}

}
