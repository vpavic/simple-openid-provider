package io.github.vpavic.oauth2.grant.client;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.TokenService;

public class ClientCredentialsGrantHandler implements GrantHandler {

	private final ClientRepository clientRepository;

	private final TokenService tokenService;

	public ClientCredentialsGrantHandler(ClientRepository clientRepository, TokenService tokenService) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");

		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
	}

	@Override
	public Tokens grant(AuthorizationGrant authorizationGrant, Scope scope, ClientAuthentication clientAuthentication)
			throws GeneralException {
		if (!(authorizationGrant instanceof ClientCredentialsGrant)) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		ClientID clientId = clientAuthentication.getClientID();
		Subject subject = new Subject(clientId.getValue());

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);

		return new Tokens(accessToken, null);
	}

}
