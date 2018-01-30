package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeContext;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.TokenService;

/**
 * OAuth 2.0 and OpenID Connect 1.0 compatible Authorization Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7636">RFC 7636: Proof Key for Code Exchange by OAuth Public Clients</a>
 * @see <a href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">OAuth 2.0 Multiple Response Type
 * Encoding Practices</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see <a href="https://openid.net/specs/openid-connect-session-1_0.html">OpenID Connect Session Management 1.0</a>
 */
public class AuthorizationHandler {

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final ScopeResolver scopeResolver;

	private boolean sessionManagementEnabled;

	public AuthorizationHandler(ClientRepository clientRepository, AuthorizationCodeService authorizationCodeService,
			TokenService tokenService, ScopeResolver scopeResolver) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		Objects.requireNonNull(scopeResolver, "scopeResolver must not be null");
		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.authorizationCodeService = authorizationCodeService;
		this.scopeResolver = scopeResolver;
	}

	public void setSessionManagementEnabled(boolean sessionManagementEnabled) {
		this.sessionManagementEnabled = sessionManagementEnabled;
	}

	public AuthorizationResponse authorize(String query, Subject subject, Instant authTime, ACR acr, List<AMR> amrs,
			SessionID sessionId) throws LoginRequiredException, NonRedirectingException {
		AuthorizationResponse authResponse;

		try {
			AuthenticationRequest authRequest = resolveAuthRequest(query);

			ResponseType responseType = authRequest.getResponseType();
			ResponseMode responseMode = authRequest.impliedResponseMode();
			ClientID clientId = authRequest.getClientID();
			URI redirectUri = authRequest.getRedirectionURI();
			State state = authRequest.getState();
			Prompt prompt = authRequest.getPrompt();
			OIDCClientInformation client = resolveClient(clientId);
			OIDCClientMetadata clientMetadata = client.getOIDCMetadata();

			validateRedirectionURI(redirectUri, clientMetadata);

			if (!clientMetadata.getResponseTypes().contains(responseType)) {
				ErrorObject error = OAuth2Error.UNAUTHORIZED_CLIENT;
				throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
			}

			if (prompt != null && prompt.contains(Prompt.Type.NONE) && subject == null) {
				ErrorObject error = OIDCError.LOGIN_REQUIRED;
				throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
			}

			if (subject == null || (prompt != null && prompt.contains(Prompt.Type.LOGIN))) {
				throw new LoginRequiredException(authRequest);
			}

			int maxAge = authRequest.getMaxAge();
			if (maxAge > 0 && authTime.plusSeconds(maxAge).isBefore(Instant.now())) {
				throw new LoginRequiredException(authRequest);
			}

			if (responseType.impliesCodeFlow()) {
				authResponse = handleAuthorizationCodeFlow(authRequest, client, subject, authTime, acr, amrs,
						sessionId);
			}
			else if (responseType.impliesImplicitFlow()) {
				authResponse = handleImplicitFlow(authRequest, client, subject, authTime, acr, amrs, sessionId);
			}
			else if (responseType.impliesHybridFlow()) {
				authResponse = handleHybridFlow(authRequest, client, subject, authTime, acr, amrs, sessionId);
			}
			else {
				ErrorObject error = OAuth2Error.UNSUPPORTED_RESPONSE_TYPE;
				throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
			}
		}
		catch (GeneralException e) {
			if (e.getRedirectionURI() == null) {
				throw new NonRedirectingException(e.getErrorObject());
			}
			else {
				authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), e.getErrorObject(), e.getState(),
						e.getResponseMode());
			}
		}

		return authResponse;
	}

	private AuthenticationRequest resolveAuthRequest(String query) throws GeneralException {
		AuthenticationRequest authRequest;

		try {
			authRequest = AuthenticationRequest.parse(query);
		}
		catch (ParseException e) {
			ClientID clientId = e.getClientID();
			URI redirectUri = e.getRedirectionURI();

			if (clientId == null || redirectUri == null) {
				throw new GeneralException(
						OAuth2Error.INVALID_REQUEST.setDescription(e.getErrorObject().getDescription()));
			}

			OIDCClientInformation client = resolveClient(clientId);
			validateRedirectionURI(redirectUri, client.getOIDCMetadata());

			throw e;
		}

		return authRequest;
	}

	private OIDCClientInformation resolveClient(ClientID clientId) throws GeneralException {
		OIDCClientInformation client = this.clientRepository.findById(clientId);

		if (client == null) {
			throw new GeneralException(
					OAuth2Error.INVALID_REQUEST.setDescription("Invalid \"client_id\" parameter: " + clientId));
		}

		return client;
	}

	private void validateRedirectionURI(URI redirectUri, OIDCClientMetadata clientMetadata) throws GeneralException {
		Set<URI> registeredRedirectionURIs = clientMetadata.getRedirectionURIs();

		if (registeredRedirectionURIs == null || !registeredRedirectionURIs.contains(redirectUri)) {
			throw new GeneralException(
					OAuth2Error.INVALID_REQUEST.setDescription("Invalid \"redirect_uri\" parameter: " + redirectUri));
		}
	}

	private AuthenticationSuccessResponse handleAuthorizationCodeFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, Subject subject, Instant authTime, ACR acr, List<AMR> amrs,
			SessionID sessionId) throws GeneralException {
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope requestedScope = authRequest.getScope();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AuthorizationCodeContext context = new AuthorizationCodeContext(subject, clientId, redirectUri, scope, authTime,
				acr, amrs, sessionId, codeChallenge, codeChallengeMethod, nonce);
		AuthorizationCode code = this.authorizationCodeService.create(context);

		return new AuthenticationSuccessResponse(redirectUri, code, null, null, authRequest.getState(), sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleImplicitFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, Subject subject, Instant authTime, ACR acr, List<AMR> amrs,
			SessionID sessionId) throws GeneralException {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope requestedScope = authRequest.getScope();
		State state = authRequest.getState();
		Nonce nonce = authRequest.getNonce();

		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, scope, authTime, acr, amrs, sessionId,
				nonce, accessToken, null);
		JWT idToken = this.tokenService.createIdToken(idTokenRequest);

		return new AuthenticationSuccessResponse(redirectUri, null, idToken, accessToken, state, sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleHybridFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, Subject subject, Instant authTime, ACR acr, List<AMR> amrs,
			SessionID sessionId) throws GeneralException {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope requestedScope = authRequest.getScope();
		State state = authRequest.getState();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AuthorizationCodeContext context = new AuthorizationCodeContext(subject, clientId, redirectUri, scope, authTime,
				acr, amrs, sessionId, codeChallenge, codeChallengeMethod, nonce);
		AuthorizationCode code = this.authorizationCodeService.create(context);
		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		JWT idToken = null;

		if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
			IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, scope, authTime, acr, amrs, sessionId,
					nonce, accessToken, code);
			idToken = this.tokenService.createIdToken(idTokenRequest);
		}

		return new AuthenticationSuccessResponse(redirectUri, code, idToken, accessToken, state, sessionState,
				responseMode);
	}

}
