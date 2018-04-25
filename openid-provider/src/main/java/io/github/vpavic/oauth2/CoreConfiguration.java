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

import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.endpoint.AuthorizationEndpoint;
import io.github.vpavic.oauth2.endpoint.AuthorizationHandler;
import io.github.vpavic.oauth2.endpoint.TokenEndpoint;
import io.github.vpavic.oauth2.endpoint.TokenHandler;
import io.github.vpavic.oauth2.endpoint.TokenRevocationEndpoint;
import io.github.vpavic.oauth2.endpoint.UserInfoEndpoint;
import io.github.vpavic.oauth2.endpoint.UserInfoHandler;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.grant.client.ClientCredentialsGrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeGrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.grant.password.PasswordAuthenticationHandler;
import io.github.vpavic.oauth2.grant.password.ResourceOwnerPasswordCredentialsGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.DefaultIdTokenService;
import io.github.vpavic.oauth2.token.DefaultRefreshTokenService;
import io.github.vpavic.oauth2.token.IdTokenService;
import io.github.vpavic.oauth2.token.JwtAccessTokenService;
import io.github.vpavic.oauth2.token.RefreshTokenService;

@Configuration
public class CoreConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final JwkSetLoader jwkSetLoader;

	private final AuthorizationCodeService authorizationCodeService;

	private final RefreshTokenStore refreshTokenStore;

	private final ClaimSource claimSource;

	private final ScopeResolver scopeResolver;

	private final PasswordAuthenticationHandler passwordAuthenticationHandler;

	public CoreConfiguration(OpenIdProviderProperties properties, ObjectProvider<ClientRepository> clientRepository,
			ObjectProvider<JwkSetLoader> jwkSetLoader,
			ObjectProvider<AuthorizationCodeService> authorizationCodeService,
			ObjectProvider<RefreshTokenStore> refreshTokenStore, ObjectProvider<ClaimSource> claimSource,
			ObjectProvider<ScopeResolver> scopeResolver,
			ObjectProvider<PasswordAuthenticationHandler> passwordAuthenticationHandler) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
		this.jwkSetLoader = jwkSetLoader.getObject();
		this.authorizationCodeService = authorizationCodeService.getObject();
		this.refreshTokenStore = refreshTokenStore.getObject();
		this.claimSource = claimSource.getObject();
		this.scopeResolver = scopeResolver.getObject();
		this.passwordAuthenticationHandler = passwordAuthenticationHandler.getObject();
	}

	@Bean
	public AccessTokenService accessTokenService() {
		JwtAccessTokenService accessTokenService = new JwtAccessTokenService(this.properties.getIssuer(),
				this.jwkSetLoader, this.claimSource);
		accessTokenService.setResourceScopes(this.properties.getAuthorization().getResourceScopes());
		accessTokenService.setAccessTokenLifetime(Duration.ofSeconds(this.properties.getAccessToken().getLifetime()));
		accessTokenService.setAccessTokenJwsAlgorithm(this.properties.getAccessToken().getJwsAlgorithm());
		accessTokenService.setAccessTokenScopeClaim(this.properties.getAccessToken().getScopeClaim());
		accessTokenService.setAccessTokenClientIdClaim(this.properties.getAccessToken().getClientIdClaim());
		accessTokenService.setAccessTokenSubjectClaims(this.properties.getAccessToken().getSubjectClaims());
		return accessTokenService;
	}

	@Bean
	public RefreshTokenService refreshTokenService() {
		DefaultRefreshTokenService refreshTokenService = new DefaultRefreshTokenService(this.refreshTokenStore);
		refreshTokenService
				.setRefreshTokenLifetime(Duration.ofSeconds(this.properties.getRefreshToken().getLifetime()));
		return refreshTokenService;
	}

	@Bean
	public IdTokenService idTokenService() {
		DefaultIdTokenService tokenService = new DefaultIdTokenService(this.properties.getIssuer(), this.jwkSetLoader,
				this.claimSource);
		tokenService.setIdTokenLifetime(Duration.ofSeconds(this.properties.getIdToken().getLifetime()));
		tokenService.setScopeClaims(this.properties.getClaim().getScopeClaims());
		tokenService.setFrontChannelLogoutEnabled(this.properties.getFrontChannelLogout().isEnabled());
		return tokenService;
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() {
		AuthorizationHandler handler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				accessTokenService(), idTokenService(), this.scopeResolver);
		handler.setSessionManagementEnabled(this.properties.getSessionManagement().isEnabled());
		return new AuthorizationEndpoint(handler);
	}

	@Bean
	public TokenHandler tokenHandler() {
		AuthorizationCodeGrantHandler authorizationCodeGrantHandler = new AuthorizationCodeGrantHandler(
				this.clientRepository, accessTokenService(), refreshTokenService(), idTokenService(),
				this.authorizationCodeService);
		ResourceOwnerPasswordCredentialsGrantHandler passwordCredentialsGrantHandler = new ResourceOwnerPasswordCredentialsGrantHandler(
				this.clientRepository, accessTokenService(), refreshTokenService(), this.scopeResolver,
				this.passwordAuthenticationHandler);
		ClientCredentialsGrantHandler clientCredentialsGrantHandler = new ClientCredentialsGrantHandler(
				this.clientRepository, this.scopeResolver, accessTokenService());
		RefreshTokenGrantHandler refreshTokenGrantHandler = new RefreshTokenGrantHandler(this.clientRepository,
				accessTokenService(), refreshTokenService(), this.refreshTokenStore);
		refreshTokenGrantHandler.setUpdateRefreshToken(this.properties.getRefreshToken().isUpdate());

		Map<Class<?>, GrantHandler> grantHandlers = new HashMap<>();
		grantHandlers.put(AuthorizationCodeGrant.class, authorizationCodeGrantHandler);
		grantHandlers.put(ResourceOwnerPasswordCredentialsGrant.class, passwordCredentialsGrantHandler);
		grantHandlers.put(ClientCredentialsGrant.class, clientCredentialsGrantHandler);
		grantHandlers.put(RefreshTokenGrant.class, refreshTokenGrantHandler);

		return new TokenHandler(grantHandlers, this.refreshTokenStore, this.properties.getIssuer(),
				this.clientRepository);
	}

	@Bean
	public TokenEndpoint tokenEndpoint() {
		return new TokenEndpoint(tokenHandler());
	}

	@Bean
	public TokenRevocationEndpoint tokenRevocationEndpoint() {
		return new TokenRevocationEndpoint(tokenHandler());
	}

	@Bean
	public UserInfoEndpoint userInfoEndpoint() {
		UserInfoHandler handler = new UserInfoHandler(accessTokenService(), this.claimSource);
		handler.setScopeClaims(this.properties.getClaim().getScopeClaims());
		return new UserInfoEndpoint(handler);
	}

}
