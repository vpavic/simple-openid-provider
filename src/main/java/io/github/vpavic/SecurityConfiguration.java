package io.github.vpavic;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.formLogin()
				.permitAll()
				.and()
			.logout()
				.and()
			.authorizeRequests()
				.mvcMatchers("/").permitAll()
				.mvcMatchers("/keys").permitAll()
				.anyRequest().denyAll();
		// @formatter:on
	}

}
