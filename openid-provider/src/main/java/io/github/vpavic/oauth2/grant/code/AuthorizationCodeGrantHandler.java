package io.github.vpavic.oauth2.grant.code;

import java.time.Instant;
import java.util.Objects;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenRequest;
import io.github.vpavic.oauth2.token.TokenService;

public class AuthorizationCodeGrantHandler implements GrantHandler {

	private final ClientRepository clientRepository;

	private final TokenService tokenService;

	private final AuthorizationCodeService authorizationCodeService;

	public AuthorizationCodeGrantHandler(ClientRepository clientRepository, TokenService tokenService,
			AuthorizationCodeService authorizationCodeService) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");

		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.authorizationCodeService = authorizationCodeService;
	}

	@Override
	public Tokens grant(AuthorizationGrant authorizationGrant, Scope scope, ClientAuthentication clientAuthentication)
			throws GeneralException {
		if (!(authorizationGrant instanceof AuthorizationCodeGrant)) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;
		AuthorizationCodeContext context = this.authorizationCodeService
				.consume(authorizationCodeGrant.getAuthorizationCode());

		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}

		CodeChallenge codeChallenge = context.getCodeChallenge();

		if (codeChallenge != null) {
			CodeChallengeMethod codeChallengeMethod = context.getCodeChallengeMethod();

			if (codeChallengeMethod == null) {
				codeChallengeMethod = CodeChallengeMethod.PLAIN;
			}

			CodeVerifier codeVerifier = authorizationCodeGrant.getCodeVerifier();

			if (codeVerifier == null
					|| !codeChallenge.equals(CodeChallenge.compute(codeChallengeMethod, codeVerifier))) {
				throw new GeneralException(OAuth2Error.INVALID_REQUEST);
			}
		}

		Subject subject = context.getSubject();
		ClientID clientId = context.getClientId();
		Scope savedScope = context.getScope();
		Instant authenticationTime = context.getAuthenticationTime();
		ACR acr = context.getAcr();
		AMR amr = context.getAmr();
		SessionID sessionId = context.getSessionId();
		Nonce nonce = context.getNonce();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, savedScope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (client.getOIDCMetadata().getGrantTypes().contains(GrantType.REFRESH_TOKEN)
				|| savedScope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, savedScope);
			refreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, savedScope, authenticationTime, acr, amr,
				sessionId, nonce, accessToken, null);
		JWT idToken = this.tokenService.createIdToken(idTokenRequest);

		return new OIDCTokens(idToken.serialize(), accessToken, refreshToken);
	}

}
