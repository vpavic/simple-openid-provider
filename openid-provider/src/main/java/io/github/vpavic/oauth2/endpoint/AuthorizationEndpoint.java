package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

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
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.code.AuthorizationCodeContext;
import io.github.vpavic.oauth2.code.AuthorizationCodeService;
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
@RequestMapping(path = AuthorizationEndpoint.PATH_MAPPING)
public class AuthorizationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/authorize";

	public static final String AUTH_REQUEST_URI_ATTRIBUTE = "continue";

	private static final String PROMPT_PARAMETER = "prompt";

	private static final String LOGIN_REDIRECT_URI = "redirect:/login";

	private static final String FORM_POST_PATH = "/form-post";

	private static final String FORM_POST_FORWARD_URI = "forward:" + PATH_MAPPING + FORM_POST_PATH;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private ACR acr = new ACR("1");

	private boolean sessionManagementEnabled;

	private List<Scope.Value> supportedScopes = Collections.singletonList(OIDCScopeValue.OPENID);

	public AuthorizationEndpoint(ClientRepository clientRepository, AuthorizationCodeService authorizationCodeService,
			TokenService tokenService) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");

		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.authorizationCodeService = authorizationCodeService;
	}

	public void setAcr(ACR acr) {
		this.acr = acr;
	}

	public void setSessionManagementEnabled(boolean sessionManagementEnabled) {
		this.sessionManagementEnabled = sessionManagementEnabled;
	}

	public void setSupportedScopes(List<Scope.Value> supportedScopes) {
		this.supportedScopes = supportedScopes;
	}

	@GetMapping
	public ModelAndView authorize(ServletWebRequest request, Authentication authentication) throws GeneralException {
		AuthenticationRequest authRequest = resolveAuthRequest(request);
		ClientID clientId = authRequest.getClientID();
		OIDCClientInformation client = resolveClient(clientId);
		validateAuthRequest(authRequest, client, authentication);

		Prompt prompt = authRequest.getPrompt();

		if (authentication == null || (prompt != null && prompt.contains(Prompt.Type.LOGIN))) {
			return loginRedirect(request, authRequest);
		}

		int maxAge = authRequest.getMaxAge();
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());

		if (maxAge > 0 && authenticationTime.plusSeconds(maxAge).isBefore(Instant.now())) {
			return loginRedirect(request, authRequest);
		}

		request.removeAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE, RequestAttributes.SCOPE_SESSION);

		ResponseType responseType = authRequest.getResponseType();
		AuthenticationSuccessResponse authResponse;

		if (responseType.impliesCodeFlow()) {
			authResponse = handleAuthorizationCodeFlow(authRequest, client, request, authentication);
		}
		else if (responseType.impliesImplicitFlow()) {
			authResponse = handleImplicitFlow(authRequest, client, request, authentication);
		}
		else if (responseType.impliesHybridFlow()) {
			authResponse = handleHybridFlow(authRequest, client, request, authentication);
		}
		else {
			ErrorObject error = OAuth2Error.UNSUPPORTED_RESPONSE_TYPE;
			URI redirectUri = authRequest.getRedirectionURI();
			ResponseMode responseMode = authRequest.getResponseMode();
			State state = authRequest.getState();

			throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
		}

		return authResponse(authResponse);
	}

	@GetMapping(path = FORM_POST_PATH)
	public ResponseEntity<String> formPost(ServletWebRequest request) {
		AuthorizationResponse authResponse = (AuthorizationResponse) request.getAttribute("authResponse",
				RequestAttributes.SCOPE_REQUEST);

		if (authResponse == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		}

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.TEXT_HTML)
				.body(prepareFormPostPage(authResponse));
		// @formatter:on
	}

	private AuthenticationRequest resolveAuthRequest(ServletWebRequest request) throws GeneralException {
		AuthenticationRequest authRequest;

		try {
			authRequest = AuthenticationRequest.parse(request.getRequest().getQueryString());
		}
		catch (ParseException e) {
			ClientID clientId = e.getClientID();
			URI redirectUri = e.getRedirectionURI();

			if (clientId == null || redirectUri == null) {
				throw new AuthorizationRequestException(e.getErrorObject());
			}

			OIDCClientInformation client = resolveClient(clientId);
			validateRedirectionURI(redirectUri, client.getOIDCMetadata());

			throw e;
		}

		return authRequest;
	}

	private OIDCClientInformation resolveClient(ClientID clientId) {
		OIDCClientInformation client = this.clientRepository.findById(clientId);

		if (client == null) {
			ErrorObject error = OAuth2Error.INVALID_REQUEST
					.setDescription("Invalid \"client_id\" parameter: " + clientId);
			throw new AuthorizationRequestException(error);
		}

		return client;
	}

	private void validateRedirectionURI(URI redirectUri, OIDCClientMetadata clientMetadata) {
		Set<URI> registeredRedirectionURIs = clientMetadata.getRedirectionURIs();

		if (registeredRedirectionURIs == null || !registeredRedirectionURIs.contains(redirectUri)) {
			ErrorObject error = OAuth2Error.INVALID_REQUEST
					.setDescription("Invalid \"redirect_uri\" parameter: " + redirectUri);
			throw new AuthorizationRequestException(error);
		}
	}

	private void validateAuthRequest(AuthenticationRequest authRequest, OIDCClientInformation client,
			Authentication authentication) throws GeneralException {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectUri = authRequest.getRedirectionURI();
		State state = authRequest.getState();
		Prompt prompt = authRequest.getPrompt();
		OIDCClientMetadata clientMetadata = client.getOIDCMetadata();

		validateRedirectionURI(redirectUri, clientMetadata);

		if (!clientMetadata.getResponseTypes().contains(responseType)) {
			ErrorObject error = OAuth2Error.UNAUTHORIZED_CLIENT;

			throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
		}

		if (prompt != null && prompt.contains(Prompt.Type.NONE) && authentication == null) {
			ErrorObject error = OIDCError.LOGIN_REQUIRED;

			throw new GeneralException(error.getDescription(), error, clientId, redirectUri, responseMode, state);
		}
	}

	private ModelAndView loginRedirect(ServletWebRequest request, AuthenticationRequest authRequest) {
		Prompt prompt = authRequest.getPrompt();
		String authRequestQuery;

		if (prompt != null && prompt.contains(Prompt.Type.LOGIN)) {
			// @formatter:off
			Map<String, String> authRequestParams = authRequest.toParameters().entrySet().stream()
					.filter(entry -> !entry.getKey().equals(PROMPT_PARAMETER))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			// @formatter:on

			authRequestQuery = URLUtils.serializeParameters(authRequestParams);
		}
		else {
			authRequestQuery = authRequest.toQueryString();
		}

		String authRequestUri = PATH_MAPPING + "?" + authRequestQuery;
		request.setAttribute(AUTH_REQUEST_URI_ATTRIBUTE, authRequestUri, RequestAttributes.SCOPE_SESSION);

		return new ModelAndView(LOGIN_REDIRECT_URI);
	}

	private AuthenticationSuccessResponse handleAuthorizationCodeFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, ServletWebRequest request, Authentication authentication) {
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectionUri = authRequest.getRedirectionURI();
		Scope scope = resolveScope(authRequest, client.getOIDCMetadata());
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		Subject subject = new Subject(authentication.getName());
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());
		ACR acr = this.acr;
		AMR amr = AMR.PWD;
		SessionID sessionId = new SessionID(request.getSessionId());
		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		AuthorizationCodeContext context = new AuthorizationCodeContext(subject, clientId, scope, authenticationTime,
				acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);
		AuthorizationCode code = this.authorizationCodeService.create(context);

		return new AuthenticationSuccessResponse(redirectionUri, code, null, null, authRequest.getState(), sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleImplicitFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, ServletWebRequest request, Authentication authentication) {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		URI redirectionUri = authRequest.getRedirectionURI();
		Scope scope = resolveScope(authRequest, client.getOIDCMetadata());
		State state = authRequest.getState();
		Nonce nonce = authRequest.getNonce();

		Subject subject = new Subject(authentication.getName());
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());
		ACR acr = this.acr;
		AMR amr = AMR.PWD;
		SessionID sessionId = new SessionID(request.getSessionId());
		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, scope, authenticationTime, acr, amr,
				sessionId, nonce, accessToken, null);
		JWT idToken = this.tokenService.createIdToken(idTokenRequest);

		return new AuthenticationSuccessResponse(redirectionUri, null, idToken, accessToken, state, sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleHybridFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, ServletWebRequest request, Authentication authentication) {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientId = authRequest.getClientID();
		URI redirectUri = authRequest.getRedirectionURI();
		Scope scope = resolveScope(authRequest, client.getOIDCMetadata());
		State state = authRequest.getState();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		Subject subject = new Subject(authentication.getName());
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());
		ACR acr = this.acr;
		AMR amr = AMR.PWD;
		SessionID sessionId = new SessionID(request.getSessionId());
		State sessionState = this.sessionManagementEnabled ? State.parse(sessionId.getValue()) : null;

		AuthorizationCodeContext context = new AuthorizationCodeContext(subject, clientId, scope, authenticationTime,
				acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);
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

	private Scope resolveScope(AuthenticationRequest authRequest, OIDCClientMetadata clientMetadata) {
		Scope requestedScope = authRequest.getScope();
		requestedScope.retainAll(this.supportedScopes);
		Scope registeredScope = clientMetadata.getScope();
		Scope resolvedScope;

		if (registeredScope == null || registeredScope.isEmpty()) {
			resolvedScope = requestedScope;
		}
		else {
			resolvedScope = new Scope();

			for (Scope.Value scope : requestedScope) {
				if (registeredScope.contains(scope)) {
					resolvedScope.add(scope);
				}
			}
		}

		return resolvedScope;
	}

	private ModelAndView authResponse(AuthorizationResponse authResponse) {
		if (ResponseMode.FORM_POST.equals(authResponse.getResponseMode())) {
			return new ModelAndView(FORM_POST_FORWARD_URI, Collections.singletonMap("authResponse", authResponse));
		}
		else {
			return new ModelAndView("redirect:" + authResponse.toURI());
		}
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

	@ExceptionHandler(GeneralException.class)
	public ModelAndView handleGeneralException(GeneralException e) {
		AuthenticationErrorResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(),
				e.getErrorObject(), e.getState(), e.getResponseMode());

		return authResponse(authResponse);
	}

}
