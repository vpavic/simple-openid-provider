package io.github.vpavic.oauth2.grant.password;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenRequest;
import io.github.vpavic.oauth2.token.TokenService;

public class ResourceOwnerPasswordCredentialsGrantHandler implements GrantHandler {

	private final ClientRepository clientRepository;

	private final TokenService tokenService;

	private final ScopeResolver scopeResolver;

	private final PasswordAuthenticationHandler passwordAuthenticationHandler;

	public ResourceOwnerPasswordCredentialsGrantHandler(ClientRepository clientRepository, TokenService tokenService,
			ScopeResolver scopeResolver, PasswordAuthenticationHandler passwordAuthenticationHandler) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(scopeResolver, "scopeResolver must not be null");
		Objects.requireNonNull(passwordAuthenticationHandler, "passwordAuthenticationHandler must not be null");

		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.scopeResolver = scopeResolver;
		this.passwordAuthenticationHandler = passwordAuthenticationHandler;
	}

	@Override
	public Tokens grant(AuthorizationGrant authorizationGrant, Scope requestedScope, ClientAuthentication clientAuthentication)
			throws GeneralException {
		if (!(authorizationGrant instanceof ResourceOwnerPasswordCredentialsGrant)) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		ResourceOwnerPasswordCredentialsGrant passwordCredentialsGrant = (ResourceOwnerPasswordCredentialsGrant) authorizationGrant;
		Subject subject = this.passwordAuthenticationHandler.authenticate(passwordCredentialsGrant);
		ClientID clientId = clientAuthentication.getClientID();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (client.getOIDCMetadata().getGrantTypes().contains(GrantType.REFRESH_TOKEN)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, scope);
			refreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		return new Tokens(accessToken, refreshToken);
	}

}
