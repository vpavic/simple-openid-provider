package io.github.vpavic.rp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		ClientRegistration clientRegistration = new ClientRegistration.Builder("test-client")
				.clientSecret("test-secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizedGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("http://localhost:8080/oauth2/authorize/code/test-client")
				.scopes("openid")
				.authorizationUri("http://localhost:6432/oauth2/authorize")
				.tokenUri("http://localhost:6432/oauth2/token")
				.userInfoUri("http://localhost:6432/oauth2/userinfo")
				.jwkSetUri("http://localhost:6432/oauth2/keys")
				.clientName("test-client")
				.clientAlias("test-client")
				.build();
		// @formatter:on

		// @formatter:off
		http
			.oauth2Login()
				.clients(clientRegistration)
				.and()
			.authorizeRequests()
				.anyRequest().authenticated();
		// @formatter:on
	}

}
