package io.github.vpavic.oauth2.grant.code;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
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
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenService;
import io.github.vpavic.oauth2.token.RefreshTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenService;

public class AuthorizationCodeGrantHandler implements GrantHandler {

	private final ClientRepository clientRepository;

	private final AccessTokenService accessTokenService;

	private final RefreshTokenService refreshTokenService;

	private final IdTokenService idTokenService;

	private final AuthorizationCodeService authorizationCodeService;

	public AuthorizationCodeGrantHandler(ClientRepository clientRepository, AccessTokenService accessTokenService,
			RefreshTokenService refreshTokenService, IdTokenService idTokenService,
			AuthorizationCodeService authorizationCodeService) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(accessTokenService, "accessTokenService must not be null");
		Objects.requireNonNull(refreshTokenService, "refreshTokenService must not be null");
		Objects.requireNonNull(idTokenService, "idTokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		this.clientRepository = clientRepository;
		this.accessTokenService = accessTokenService;
		this.refreshTokenService = refreshTokenService;
		this.idTokenService = idTokenService;
		this.authorizationCodeService = authorizationCodeService;
	}

	@Override
	public Tokens grant(TokenRequest tokenRequest) throws GeneralException {
		if (!(tokenRequest.getAuthorizationGrant() instanceof AuthorizationCodeGrant)) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) tokenRequest.getAuthorizationGrant();
		AuthorizationCodeContext context = this.authorizationCodeService
				.consume(authorizationCodeGrant.getAuthorizationCode());

		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		if (!context.getClientId().equals(resolveClientId(tokenRequest))) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		if (!context.getRedirectUri().equals(authorizationCodeGrant.getRedirectionURI())) {
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
		List<AMR> amr = context.getAmrs();
		SessionID sessionId = context.getSessionId();
		Nonce nonce = context.getNonce();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, savedScope);
		AccessToken accessToken = this.accessTokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (client.getOIDCMetadata().getGrantTypes().contains(GrantType.REFRESH_TOKEN)
				|| savedScope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, savedScope);
			refreshToken = this.refreshTokenService.createRefreshToken(refreshTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, savedScope, authenticationTime, acr, amr,
				sessionId, nonce, accessToken, null);
		JWT idToken = this.idTokenService.createIdToken(idTokenRequest);

		return new OIDCTokens(idToken.serialize(), accessToken, refreshToken);
	}

	private static ClientID resolveClientId(TokenRequest tokenRequest) {
		ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
		return (clientAuthentication != null) ? clientAuthentication.getClientID() : tokenRequest.getClientID();
	}

}
