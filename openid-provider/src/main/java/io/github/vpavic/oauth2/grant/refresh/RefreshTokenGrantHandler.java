package io.github.vpavic.oauth2.grant.refresh;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
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
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenRequest;
import io.github.vpavic.oauth2.token.TokenService;

public class RefreshTokenGrantHandler implements GrantHandler {

	private boolean updateRefreshToken;

	private final ClientRepository clientRepository;

	private final TokenService tokenService;

	private final RefreshTokenStore refreshTokenStore;

	public RefreshTokenGrantHandler(ClientRepository clientRepository, TokenService tokenService,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");

		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public Tokens grant(AuthorizationGrant authorizationGrant, Scope scope, ClientAuthentication clientAuthentication)
			throws GeneralException {
		if (!(authorizationGrant instanceof RefreshTokenGrant)) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		RefreshTokenGrant refreshTokenGrant = (RefreshTokenGrant) authorizationGrant;
		RefreshToken refreshToken = refreshTokenGrant.getRefreshToken();

		RefreshTokenContext context = this.refreshTokenStore.load(refreshToken);
		Subject subject = context.getSubject();
		ClientID clientId = context.getClientId();
		Scope savedScope = context.getScope();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, savedScope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken updatedRefreshToken = null;

		if (this.updateRefreshToken) {
			this.refreshTokenStore.revoke(refreshToken);
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, savedScope);
			updatedRefreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		return new Tokens(accessToken, updatedRefreshToken);
	}

	public void setUpdateRefreshToken(boolean updateRefreshToken) {
		this.updateRefreshToken = updateRefreshToken;
	}

}
