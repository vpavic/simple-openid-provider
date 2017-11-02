package io.github.vpavic.oauth2;

import java.time.Duration;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;

import io.github.vpavic.oauth2.authorization.AuthorizationEndpoint;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.token.AccessTokenClaimsMapper;
import io.github.vpavic.oauth2.token.AuthorizationCodeService;
import io.github.vpavic.oauth2.token.DefaultTokenService;
import io.github.vpavic.oauth2.token.IdTokenClaimsMapper;
import io.github.vpavic.oauth2.token.RefreshTokenStore;
import io.github.vpavic.oauth2.token.TokenEndpoint;
import io.github.vpavic.oauth2.token.TokenRevocationEndpoint;
import io.github.vpavic.oauth2.token.TokenService;
import io.github.vpavic.oauth2.userinfo.BearerAccessTokenAuthenticationFilter;
import io.github.vpavic.oauth2.userinfo.UserInfoEndpoint;
import io.github.vpavic.oauth2.userinfo.UserInfoMapper;

@Configuration
@Import({ TokenSecurityConfiguration.class, UserInfoSecurityConfiguration.class })
public class CoreConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final JwkSetLoader jwkSetLoader;

	private final AuthenticationManager authenticationManager;

	private final AuthorizationCodeService authorizationCodeService;

	private final RefreshTokenStore refreshTokenStore;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final UserInfoMapper userInfoMapper;

	public CoreConfiguration(OpenIdProviderProperties properties, ObjectProvider<ClientRepository> clientRepository,
			ObjectProvider<JwkSetLoader> jwkSetLoader, ObjectProvider<AuthenticationManager> authenticationManager,
			ObjectProvider<AuthorizationCodeService> authorizationCodeService,
			ObjectProvider<RefreshTokenStore> refreshTokenStore,
			ObjectProvider<AccessTokenClaimsMapper> accessTokenClaimsMapper,
			ObjectProvider<IdTokenClaimsMapper> idTokenClaimsMapper, ObjectProvider<UserInfoMapper> userInfoMapper) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
		this.jwkSetLoader = jwkSetLoader.getObject();
		this.authenticationManager = authenticationManager.getObject();
		this.authorizationCodeService = authorizationCodeService.getObject();
		this.refreshTokenStore = refreshTokenStore.getObject();
		this.accessTokenClaimsMapper = accessTokenClaimsMapper.getObject();
		this.idTokenClaimsMapper = idTokenClaimsMapper.getObject();
		this.userInfoMapper = userInfoMapper.getObject();
	}

	@Bean
	public TokenService tokenService() {
		DefaultTokenService tokenService = new DefaultTokenService(this.properties.getIssuer(), this.jwkSetLoader,
				this.refreshTokenStore);
		tokenService.setAccessTokenJwsAlgorithm(this.properties.getAccessToken().getJwsAlgorithm());
		tokenService.setAccessTokenLifetime(Duration.ofSeconds(this.properties.getAccessToken().getLifetime()));
		tokenService.setRefreshTokenLifetime(Duration.ofSeconds(this.properties.getRefreshToken().getLifetime()));
		tokenService.setIdTokenLifetime(Duration.ofSeconds(this.properties.getIdToken().getLifetime()));
		tokenService.setFrontChannelLogoutEnabled(this.properties.getFrontChannelLogout().isEnabled());
		tokenService.setResourceScopes(this.properties.getAuthorization().getResourceScopes());
		return tokenService;
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() {
		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint(this.clientRepository,
				this.authorizationCodeService, tokenService(), this.accessTokenClaimsMapper, this.idTokenClaimsMapper,
				this.userInfoMapper);
		authorizationEndpoint.setAcr(this.properties.getAuthorization().getAcrs().get(0));
		authorizationEndpoint.setSessionManagementEnabled(this.properties.getSessionManagement().isEnabled());
		authorizationEndpoint.setSupportedScopes(this.properties.getAuthorization().getSupportedScopes());
		return authorizationEndpoint;
	}

	@Bean
	public TokenEndpoint tokenEndpoint() {
		TokenEndpoint endpoint = new TokenEndpoint(this.properties.getIssuer(), this.clientRepository,
				this.authorizationCodeService, tokenService(), this.authenticationManager, this.refreshTokenStore,
				this.accessTokenClaimsMapper, this.idTokenClaimsMapper);
		endpoint.setUpdateRefreshToken(this.properties.getRefreshToken().isUpdate());
		return endpoint;
	}

	@Bean
	public TokenRevocationEndpoint tokenRevocationEndpoint() {
		return new TokenRevocationEndpoint(this.properties.getIssuer(), this.clientRepository, this.refreshTokenStore);
	}

	@Bean
	public UserInfoEndpoint userInfoEndpoint() {
		return new UserInfoEndpoint(this.userInfoMapper);
	}

	@Bean
	public BearerAccessTokenAuthenticationFilter userInfoAuthenticationFilter() {
		BearerAccessTokenAuthenticationFilter filter = new BearerAccessTokenAuthenticationFilter(
				this.properties.getIssuer(), this.jwkSetLoader);
		filter.setJwsAlgorithm(this.properties.getAccessToken().getJwsAlgorithm());
		return filter;
	}

}
