package io.github.vpavic.oauth2.grant.refresh;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.RefreshTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenService;

public class RefreshTokenGrantHandler implements GrantHandler {

	private boolean updateRefreshToken;

	private final ClientRepository clientRepository;

	private final AccessTokenService accessTokenService;

	private final RefreshTokenService refreshTokenService;

	private final RefreshTokenStore refreshTokenStore;

	public RefreshTokenGrantHandler(ClientRepository clientRepository, AccessTokenService accessTokenService,
			RefreshTokenService refreshTokenService, RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(accessTokenService, "accessTokenService must not be null");
		Objects.requireNonNull(refreshTokenService, "refreshTokenService must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");
		this.clientRepository = clientRepository;
		this.accessTokenService = accessTokenService;
		this.refreshTokenService = refreshTokenService;
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public Tokens grant(TokenRequest tokenRequest) throws GeneralException {
		if (!(tokenRequest.getAuthorizationGrant() instanceof RefreshTokenGrant)) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		RefreshToken refreshToken = ((RefreshTokenGrant) tokenRequest.getAuthorizationGrant()).getRefreshToken();
		RefreshTokenContext context = this.refreshTokenStore.load(refreshToken);

		Subject subject = context.getSubject();
		ClientID clientId = context.getClientId();
		Scope originalScope = context.getScope();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, originalScope);
		AccessToken accessToken = this.accessTokenService.createAccessToken(accessTokenRequest);
		RefreshToken updatedRefreshToken = null;

		if (this.updateRefreshToken) {
			this.refreshTokenStore.revoke(refreshToken);
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, originalScope);
			updatedRefreshToken = this.refreshTokenService.createRefreshToken(refreshTokenRequest);
		}

		return new Tokens(accessToken, updatedRefreshToken);
	}

	public void setUpdateRefreshToken(boolean updateRefreshToken) {
		this.updateRefreshToken = updateRefreshToken;
	}

}
