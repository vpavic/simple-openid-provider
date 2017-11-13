package io.github.vpavic.oauth2;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;

import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.endpoint.AuthorizationEndpoint;
import io.github.vpavic.oauth2.endpoint.TokenEndpoint;
import io.github.vpavic.oauth2.endpoint.TokenRevocationEndpoint;
import io.github.vpavic.oauth2.endpoint.UserInfoEndpoint;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.grant.client.ClientCredentialsGrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeGrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.grant.password.ResourceOwnerPasswordCredentialsGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.DefaultTokenService;
import io.github.vpavic.oauth2.token.TokenService;

@Configuration
@Import(TokenSecurityConfiguration.class)
public class CoreConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final JwkSetLoader jwkSetLoader;

	private final AuthenticationManager authenticationManager;

	private final AuthorizationCodeService authorizationCodeService;

	private final RefreshTokenStore refreshTokenStore;

	private final ClaimSource claimSource;

	private final ScopeResolver scopeResolver;

	public CoreConfiguration(OpenIdProviderProperties properties, ObjectProvider<ClientRepository> clientRepository,
			ObjectProvider<JwkSetLoader> jwkSetLoader, ObjectProvider<AuthenticationManager> authenticationManager,
			ObjectProvider<AuthorizationCodeService> authorizationCodeService,
			ObjectProvider<RefreshTokenStore> refreshTokenStore, ObjectProvider<ClaimSource> claimSource,
			ObjectProvider<ScopeResolver> scopeResolver) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
		this.jwkSetLoader = jwkSetLoader.getObject();
		this.authenticationManager = authenticationManager.getObject();
		this.authorizationCodeService = authorizationCodeService.getObject();
		this.refreshTokenStore = refreshTokenStore.getObject();
		this.claimSource = claimSource.getObject();
		this.scopeResolver = scopeResolver.getObject();
	}

	@Bean
	public TokenService tokenService() {
		DefaultTokenService tokenService = new DefaultTokenService(this.properties.getIssuer(), this.jwkSetLoader,
				this.claimSource, this.refreshTokenStore);
		tokenService.setResourceScopes(this.properties.getAuthorization().getResourceScopes());
		tokenService.setAccessTokenLifetime(Duration.ofSeconds(this.properties.getAccessToken().getLifetime()));
		tokenService.setAccessTokenJwsAlgorithm(this.properties.getAccessToken().getJwsAlgorithm());
		tokenService.setAccessTokenSubjectClaims(this.properties.getAccessToken().getSubjectClaims());
		tokenService.setRefreshTokenLifetime(Duration.ofSeconds(this.properties.getRefreshToken().getLifetime()));
		tokenService.setIdTokenLifetime(Duration.ofSeconds(this.properties.getIdToken().getLifetime()));
		tokenService.setScopeClaims(this.properties.getClaim().getScopeClaims());
		tokenService.setFrontChannelLogoutEnabled(this.properties.getFrontChannelLogout().isEnabled());
		return tokenService;
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() {
		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint(this.clientRepository,
				this.authorizationCodeService, tokenService(), this.scopeResolver);
		authorizationEndpoint.setAcr(this.properties.getAuthorization().getAcrs().get(1));
		authorizationEndpoint.setSessionManagementEnabled(this.properties.getSessionManagement().isEnabled());
		return authorizationEndpoint;
	}

	@Bean
	public TokenEndpoint tokenEndpoint() {
		AuthorizationCodeGrantHandler authorizationCodeGrantHandler = new AuthorizationCodeGrantHandler(
				this.clientRepository, tokenService(), this.authorizationCodeService);
		ResourceOwnerPasswordCredentialsGrantHandler passwordCredentialsGrantHandler = new ResourceOwnerPasswordCredentialsGrantHandler(
				this.clientRepository, tokenService(), this.authenticationManager);
		ClientCredentialsGrantHandler clientCredentialsGrantHandler = new ClientCredentialsGrantHandler(
				this.clientRepository, tokenService());
		RefreshTokenGrantHandler refreshTokenGrantHandler = new RefreshTokenGrantHandler(this.clientRepository,
				tokenService(), this.refreshTokenStore);
		refreshTokenGrantHandler.setUpdateRefreshToken(this.properties.getRefreshToken().isUpdate());

		Map<Class<?>, GrantHandler> grantHandlers = new HashMap<>();
		grantHandlers.put(AuthorizationCodeGrant.class, authorizationCodeGrantHandler);
		grantHandlers.put(ResourceOwnerPasswordCredentialsGrant.class, passwordCredentialsGrantHandler);
		grantHandlers.put(ClientCredentialsGrant.class, clientCredentialsGrantHandler);
		grantHandlers.put(RefreshTokenGrant.class, refreshTokenGrantHandler);

		return new TokenEndpoint(grantHandlers, this.properties.getIssuer(), this.clientRepository);
	}

	@Bean
	public TokenRevocationEndpoint tokenRevocationEndpoint() {
		return new TokenRevocationEndpoint(this.properties.getIssuer(), this.clientRepository, this.refreshTokenStore);
	}

	@Bean
	public UserInfoEndpoint userInfoEndpoint() {
		UserInfoEndpoint endpoint = new UserInfoEndpoint(this.claimSource);
		endpoint.setScopeClaims(this.properties.getClaim().getScopeClaims());
		return endpoint;
	}

	@Bean
	public UserInfoSecurityConfiguration userInfoSecurityConfiguration() {
		UserInfoSecurityConfiguration userInfoSecurityConfiguration = new UserInfoSecurityConfiguration(
				this.properties.getIssuer(), this.jwkSetLoader);
		userInfoSecurityConfiguration.setAccessTokenJwsAlgorithm(this.properties.getAccessToken().getJwsAlgorithm());
		return userInfoSecurityConfiguration;
	}

}
