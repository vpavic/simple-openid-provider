package io.github.vpavic.rp.config;

import java.net.URI;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.user.converter.UserInfoConverter;
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
				.redirectUri("http://localhost:7979/oauth2/authorize/code/test-client")
				.scopes("openid")
				.authorizationUri("http://localhost:6432/authorize")
				.tokenUri("http://localhost:6432/token")
				.userInfoUri("http://localhost:6432/userinfo")
				.clientName("test-client")
				.clientAlias("test-client")
				.build();
		// @formatter:on

		// @formatter:off
		http
			.oauth2Login()
				.clients(clientRegistration)
				.userInfoEndpoint()
					.userInfoTypeConverter(new UserInfoConverter(),
							new URI("http://localhost:6432/userinfo"))
				.and()
			.authorizeRequests()
				.anyRequest().authenticated();
		// @formatter:on
	}

}
