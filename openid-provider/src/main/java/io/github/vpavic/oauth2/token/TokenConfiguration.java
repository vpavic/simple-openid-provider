package io.github.vpavic.oauth2.token;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

@Configuration
public class TokenConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final JwkSetLoader jwkSetLoader;

	private final AuthenticationManager authenticationManager;

	private final AuthorizationCodeService authorizationCodeService;

	private final RefreshTokenStore refreshTokenStore;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	public TokenConfiguration(OpenIdProviderProperties properties, ObjectProvider<ClientRepository> clientRepository,
			ObjectProvider<JwkSetLoader> jwkSetLoader, ObjectProvider<AuthenticationManager> authenticationManager,
			ObjectProvider<AuthorizationCodeService> authorizationCodeService,
			ObjectProvider<RefreshTokenStore> refreshTokenStore,
			ObjectProvider<AccessTokenClaimsMapper> accessTokenClaimsMapper,
			ObjectProvider<IdTokenClaimsMapper> idTokenClaimsMapper) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
		this.jwkSetLoader = jwkSetLoader.getObject();
		this.authenticationManager = authenticationManager.getObject();
		this.authorizationCodeService = authorizationCodeService.getObject();
		this.refreshTokenStore = refreshTokenStore.getObject();
		this.accessTokenClaimsMapper = accessTokenClaimsMapper.getObject();
		this.idTokenClaimsMapper = idTokenClaimsMapper.getObject();
	}

	@Bean
	public TokenService tokenService() {
		return new DefaultTokenService(this.properties, this.jwkSetLoader, this.refreshTokenStore);
	}

	@Bean
	public TokenEndpoint tokenEndpoint() {
		return new TokenEndpoint(this.properties, this.clientRepository, this.authorizationCodeService, tokenService(),
				this.authenticationManager, this.refreshTokenStore, this.accessTokenClaimsMapper,
				this.idTokenClaimsMapper);
	}

	@Bean
	public TokenRevocationEndpoint tokenRevocationEndpoint() {
		return new TokenRevocationEndpoint(this.properties, this.clientRepository, this.refreshTokenStore);
	}

	@Order(97)
	@Configuration
	static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(TokenEndpoint.PATH_MAPPING, TokenRevocationEndpoint.PATH_MAPPING)
					.and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

}
