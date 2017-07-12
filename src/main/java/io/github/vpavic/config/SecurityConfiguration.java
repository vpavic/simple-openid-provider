package io.github.vpavic.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;

@Configuration
public class SecurityConfiguration {

	@Order(0)
	@Configuration
	static class EndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("test-client")
						.password("test-secret")
						.authorities(AuthorityUtils.NO_AUTHORITIES);
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers("/keys", "/token")
					.and()
				.csrf()
					.disable()
				.httpBasic()
					.realmName("nimbus-oidc-provider")
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.NEVER)
					.and()
				.authorizeRequests()
					.mvcMatchers("/keys").permitAll()
					.mvcMatchers("/token").fullyAuthenticated();
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
					.antMatchers("/", "/login", "/logout", "/authorize")
					.and()
				.formLogin()
					.permitAll()
					.and()
				.logout()
					.and()
				.authorizeRequests()
					.mvcMatchers("/").permitAll()
					.mvcMatchers("/authorize").authenticated();
			// @formatter:on
		}

	}

}
