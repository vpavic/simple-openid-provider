package io.github.vpavic.rp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class RelyingPartyApplication {

	public static void main(String[] args) {
		SpringApplication.run(RelyingPartyApplication.class, args);
	}

	@GetMapping(path = "/")
	public String home(Authentication authentication) {
		return authentication.getPrincipal().toString();
	}

	@Configuration
	static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			ClientRegistration clientRegistration = new ClientRegistration.Builder("test-client")
					.clientSecret("test-secret")
					.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.redirectUri("http://localhost:8080/oauth2/authorize/code/test-client")
					.scope("openid")
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

}
