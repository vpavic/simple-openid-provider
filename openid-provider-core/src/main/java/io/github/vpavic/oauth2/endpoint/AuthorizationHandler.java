package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
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
import io.github.vpavic.oauth2.subject.SubjectResolver;
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

	public static final String AUTH_REQUEST_URI_ATTRIBUTE = "continue";

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final SubjectResolver subjectResolver;

	private final ScopeResolver scopeResolver;

	private ACR acr = new ACR("1");

	private boolean sessionManagementEnabled;

	public AuthorizationHandler(ClientRepository clientRepository, AuthorizationCodeService authorizationCodeService,
			TokenService tokenService, SubjectResolver subjectResolver, ScopeResolver scopeResolver) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		Objects.requireNonNull(subjectResolver, "subjectResolver must not be null");
		Objects.requireNonNull(scopeResolver, "scopeResolver must not be null");
		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.authorizationCodeService = authorizationCodeService;
		this.subjectResolver = subjectResolver;
		this.scopeResolver = scopeResolver;
	}

	public void setAcr(ACR acr) {
		this.acr = acr;
	}

	public void setSessionManagementEnabled(boolean sessionManagementEnabled) {
		this.sessionManagementEnabled = sessionManagementEnabled;
	}

	public void authorize(HttpServletRequest request, HttpServletResponse response) throws IOException {
		AuthorizationResponse authResponse;

		try {
			AuthenticationRequest authRequest = resolveAuthRequest(request);

			ResponseType responseType = authRequest.getResponseType();
			ResponseMode responseMode = authRequest.impliedResponseMode();
			ClientID clientId = authRequest.getClientID();
			URI redirectUri = authRequest.getRedirectionURI();
			State state = authRequest.getState();
			Prompt prompt = authRequest.getPrompt();
			OIDCClientInformation client = resolveClient(clientId);
			OIDCClientMetadata clientMetadata = client.getOIDCMetadata();
			Subject subject = this.subjectResolver.resolveSubject(request);
			boolean authenticated = subject != null;

			validateRedirectionURI(redirectUri, clientMetadata);

			if (!clientMetadata.getResponseTypes().contains(responseType)) {
				ErrorObject error = OAuth2Error.UNAUTHORIZED_CLIENT;
				throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
			}

			if (prompt != null && prompt.contains(Prompt.Type.NONE) && !authenticated) {
				ErrorObject error = OIDCError.LOGIN_REQUIRED;
				throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
			}

			if (!authenticated || (prompt != null && prompt.contains(Prompt.Type.LOGIN))) {
				loginRedirect(request, response, authRequest);
				return;
			}

			int maxAge = authRequest.getMaxAge();
			Instant authenticationTime = Instant.ofEpochMilli(request.getSession().getCreationTime());

			if (maxAge > 0 && authenticationTime.plusSeconds(maxAge).isBefore(Instant.now())) {
				loginRedirect(request, response, authRequest);
				return;
			}

			request.getSession().removeAttribute(AuthorizationHandler.AUTH_REQUEST_URI_ATTRIBUTE);

			if (responseType.impliesCodeFlow()) {
				authResponse = handleAuthorizationCodeFlow(authRequest, client, request, subject);
			}
			else if (responseType.impliesImplicitFlow()) {
				authResponse = handleImplicitFlow(authRequest, client, request, subject);
			}
			else if (responseType.impliesHybridFlow()) {
				authResponse = handleHybridFlow(authRequest, client, request, subject);
			}
			else {
				ErrorObject error = OAuth2Error.UNSUPPORTED_RESPONSE_TYPE;
				throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
			}
		}
		catch (GeneralException e) {
			ErrorObject error = e.getErrorObject();
			if (e.getRedirectionURI() == null) {
				response.sendError(error.getHTTPStatusCode(), error.getDescription());
				return;
			}
			else {
				authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), error, e.getState(),
						e.getResponseMode());
			}
		}

		if (ResponseMode.FORM_POST.equals(authResponse.getResponseMode())) {
			response.setContentType("text/html");

			PrintWriter writer = response.getWriter();
			writer.print(prepareFormPostPage(authResponse));
			writer.close();
		}
		else {
			ServletUtils.applyHTTPResponse(authResponse.toHTTPResponse(), response);
		}
	}

	private AuthenticationRequest resolveAuthRequest(HttpServletRequest request) throws GeneralException {
		AuthenticationRequest authRequest;

		try {
			authRequest = AuthenticationRequest.parse(request.getQueryString());
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

	private void loginRedirect(HttpServletRequest request, HttpServletResponse response,
			AuthenticationRequest authRequest) throws IOException {
		Prompt prompt = authRequest.getPrompt();
		String authRequestQuery;

		if (prompt != null && prompt.contains(Prompt.Type.LOGIN)) {
			// @formatter:off
			Map<String, String> authRequestParams = authRequest.toParameters().entrySet().stream()
					.filter(entry -> !entry.getKey().equals("prompt"))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			// @formatter:on

			authRequestQuery = URLUtils.serializeParameters(authRequestParams);
		}
		else {
			authRequestQuery = authRequest.toQueryString();
		}

		String authRequestUri = "/oauth2/authorize?" + authRequestQuery;
		request.getSession().setAttribute(AUTH_REQUEST_URI_ATTRIBUTE, authRequestUri);

		response.sendRedirect("/login");
	}

	private AuthenticationSuccessResponse handleAuthorizationCodeFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, HttpServletRequest request, Subject subject) throws GeneralException {
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope requestedScope = authRequest.getScope();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		Instant authenticationTime = Instant.ofEpochMilli(request.getSession().getCreationTime());
		ACR acr = this.acr;
		AMR amr = AMR.PWD;
		SessionID sessionId = new SessionID(request.getSession().getId());
		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AuthorizationCodeContext context = new AuthorizationCodeContext(subject, clientId, redirectUri, scope,
				authenticationTime, acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);
		AuthorizationCode code = this.authorizationCodeService.create(context);

		return new AuthenticationSuccessResponse(redirectUri, code, null, null, authRequest.getState(), sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleImplicitFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, HttpServletRequest request, Subject subject) throws GeneralException {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope requestedScope = authRequest.getScope();
		State state = authRequest.getState();
		Nonce nonce = authRequest.getNonce();

		Instant authenticationTime = Instant.ofEpochMilli(request.getSession().getCreationTime());
		ACR acr = this.acr;
		AMR amr = AMR.PWD;
		SessionID sessionId = new SessionID(request.getSession().getId());
		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, scope, authenticationTime, acr, amr,
				sessionId, nonce, accessToken, null);
		JWT idToken = this.tokenService.createIdToken(idTokenRequest);

		return new AuthenticationSuccessResponse(redirectUri, null, idToken, accessToken, state, sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleHybridFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, HttpServletRequest request, Subject subject) throws GeneralException {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope requestedScope = authRequest.getScope();
		State state = authRequest.getState();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		Instant authenticationTime = Instant.ofEpochMilli(request.getSession().getCreationTime());
		ACR acr = this.acr;
		AMR amr = AMR.PWD;
		SessionID sessionId = new SessionID(request.getSession().getId());
		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		Scope scope = this.scopeResolver.resolve(subject, requestedScope, client.getOIDCMetadata());
		AuthorizationCodeContext context = new AuthorizationCodeContext(subject, clientId, redirectUri, scope,
				authenticationTime, acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);
		AuthorizationCode code = this.authorizationCodeService.create(context);
		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		JWT idToken = null;

		if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
			IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, scope, authenticationTime, acr, amr,
					sessionId, nonce, accessToken, code);
			idToken = this.tokenService.createIdToken(idTokenRequest);
		}

		return new AuthenticationSuccessResponse(redirectUri, code, idToken, accessToken, state, sessionState,
				responseMode);
	}

	private String prepareFormPostPage(AuthorizationResponse authResponse) {
		State state = authResponse.getState();
		AuthorizationCode code = null;
		AccessToken accessToken = null;
		JWT idToken = null;
		State sessionState = null;

		if (authResponse instanceof AuthenticationSuccessResponse) {
			AuthenticationSuccessResponse authSuccessResponse = (AuthenticationSuccessResponse) authResponse;
			code = authSuccessResponse.getAuthorizationCode();
			accessToken = authSuccessResponse.getAccessToken();
			idToken = authSuccessResponse.getIDToken();
			sessionState = authSuccessResponse.getSessionState();
		}

		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>");
		sb.append("<html>");
		sb.append("<head>");
		sb.append("<meta charset=\"utf-8\">");
		sb.append("<title>Form Post</title>");
		sb.append("</head>");
		sb.append("<body onload=\"document.forms[0].submit()\">");
		sb.append("<form method=\"post\" action=\"").append(authResponse.getRedirectionURI()).append("\">");
		if (code != null) {
			sb.append("<input type=\"hidden\" name=\"code\" value=\"").append(code).append("\"/>");
		}
		if (accessToken != null) {
			sb.append("<input type=\"hidden\" name=\"access_token\" value=\"").append(accessToken).append("\"/>");
		}
		if (idToken != null) {
			sb.append("<input type=\"hidden\" name=\"id_token\" value=\"").append(idToken).append("\"/>");
		}
		if (state != null) {
			sb.append("<input type=\"hidden\" name=\"state\" value=\"").append(state).append("\"/>");
		}
		if (sessionState != null) {
			sb.append("<input type=\"hidden\" name=\"session_state\" value=\"").append(sessionState).append("\"/>");
		}
		sb.append("</form>");
		sb.append("</body>");
		sb.append("</html>");

		return sb.toString();
	}

}
