package io.github.vpavic.op.oauth2.authorization;

import java.net.URI;
import java.time.Instant;
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
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.op.oauth2.client.ClientRepository;
import io.github.vpavic.op.oauth2.code.AuthorizationCodeContext;
import io.github.vpavic.op.oauth2.code.AuthorizationCodeService;
import io.github.vpavic.op.oauth2.token.AccessTokenClaimsMapper;
import io.github.vpavic.op.oauth2.token.AccessTokenRequest;
import io.github.vpavic.op.oauth2.token.IdTokenClaimsMapper;
import io.github.vpavic.op.oauth2.token.IdTokenRequest;
import io.github.vpavic.op.oauth2.token.TokenService;
import io.github.vpavic.op.oauth2.userinfo.UserInfoMapper;

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
@Controller
@RequestMapping(path = AuthorizationEndpoint.PATH_MAPPING)
public class AuthorizationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/authorize";

	public static final String AUTH_REQUEST_URI_ATTRIBUTE = "continue";

	private static final String PROMPT_PARAMETER = "prompt";

	private static final String LOGIN_REDIRECT_URI = "redirect:/login";

	private static final String FORM_POST_VIEW_NAME = "oauth2/form-post";

	private final OIDCProviderMetadata providerMetadata;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final UserInfoMapper userInfoMapper;

	public AuthorizationEndpoint(OIDCProviderMetadata providerMetadata, ClientRepository clientRepository,
			AuthorizationCodeService authorizationCodeService, TokenService tokenService,
			AccessTokenClaimsMapper accessTokenClaimsMapper, IdTokenClaimsMapper idTokenClaimsMapper,
			UserInfoMapper userInfoMapper) {
		Objects.requireNonNull(providerMetadata, "providerMetadata must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		Objects.requireNonNull(accessTokenClaimsMapper, "accessTokenClaimsMapper must not be null");
		Objects.requireNonNull(idTokenClaimsMapper, "idTokenClaimsMapper must not be null");
		Objects.requireNonNull(userInfoMapper, "userInfoMapper must not be null");

		this.providerMetadata = providerMetadata;
		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.authorizationCodeService = authorizationCodeService;
		this.accessTokenClaimsMapper = accessTokenClaimsMapper;
		this.idTokenClaimsMapper = idTokenClaimsMapper;
		this.userInfoMapper = userInfoMapper;
	}

	@GetMapping
	public String authorize(ServletWebRequest request, Authentication authentication, Model model)
			throws GeneralException {
		AuthenticationRequest authRequest = resolveAuthRequest(request);
		OIDCClientInformation client = resolveClient(authRequest.getClientID());
		validateAuthRequest(authRequest, client, authentication);

		Prompt prompt = authRequest.getPrompt();

		if (authentication == null || (prompt != null && prompt.contains(Prompt.Type.LOGIN))) {
			return redirectToLoginPage(request, authRequest);
		}

		int maxAge = authRequest.getMaxAge();
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());

		if (maxAge > 0 && authenticationTime.plusSeconds(maxAge).isBefore(Instant.now())) {
			return redirectToLoginPage(request, authRequest);
		}

		request.removeAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE, RequestAttributes.SCOPE_SESSION);

		ResponseType responseType = authRequest.getResponseType();
		AuthenticationSuccessResponse authResponse;

		if (responseType.impliesCodeFlow()) {
			authResponse = handleAuthorizationCodeFlow(authRequest, client, request, authentication);
		}
		else if (!responseType.contains(ResponseType.Value.CODE)) {
			authResponse = handleImplicitFlow(authRequest, client, request, authentication);
		}
		else {
			authResponse = handleHybridFlow(authRequest, client, request, authentication);
		}

		return prepareResponse(authResponse, model);
	}

	private AuthenticationRequest resolveAuthRequest(ServletWebRequest request) throws GeneralException {
		AuthenticationRequest authRequest;

		try {
			authRequest = AuthenticationRequest.parse(request.getRequest().getQueryString());
		}
		catch (ParseException e) {
			ClientID clientID = e.getClientID();
			URI redirectionURI = e.getRedirectionURI();

			if (clientID == null || redirectionURI == null) {
				throw new AuthorizationRequestException(e.getErrorObject());
			}

			OIDCClientInformation client = resolveClient(clientID);
			validateRedirectionURI(redirectionURI, client.getOIDCMetadata());

			throw e;
		}

		return authRequest;
	}

	private OIDCClientInformation resolveClient(ClientID clientID) {
		OIDCClientInformation client = this.clientRepository.findByClientId(clientID);

		if (client == null) {
			ErrorObject error = OAuth2Error.INVALID_REQUEST
					.setDescription("Invalid \"client_id\" parameter: " + clientID);
			throw new AuthorizationRequestException(error);
		}

		return client;
	}

	private void validateRedirectionURI(URI redirectionURI, OIDCClientMetadata clientMetadata) {
		Set<URI> registeredRedirectionURIs = clientMetadata.getRedirectionURIs();

		if (registeredRedirectionURIs == null || !registeredRedirectionURIs.contains(redirectionURI)) {
			ErrorObject error = OAuth2Error.INVALID_REQUEST
					.setDescription("Invalid \"redirect_uri\" parameter: " + redirectionURI);
			throw new AuthorizationRequestException(error);
		}
	}

	private void validateAuthRequest(AuthenticationRequest authRequest, OIDCClientInformation client,
			Authentication authentication) throws GeneralException {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientID = authRequest.getClientID();
		URI redirectionURI = authRequest.getRedirectionURI();
		State state = authRequest.getState();
		Prompt prompt = authRequest.getPrompt();
		OIDCClientMetadata clientMetadata = client.getOIDCMetadata();

		validateRedirectionURI(redirectionURI, clientMetadata);

		if (!clientMetadata.getResponseTypes().contains(responseType)) {
			ErrorObject error = OAuth2Error.UNAUTHORIZED_CLIENT;

			throw new GeneralException(error.getDescription(), error, clientID, redirectionURI, responseMode, state);
		}

		if (prompt != null && prompt.contains(Prompt.Type.NONE) && authentication == null) {
			ErrorObject error = OIDCError.LOGIN_REQUIRED;

			throw new GeneralException(error.getDescription(), error, clientID, redirectionURI, responseMode, state);
		}
	}

	private String redirectToLoginPage(ServletWebRequest request, AuthenticationRequest authRequest) {
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

		return LOGIN_REDIRECT_URI;
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

		String principal = authentication.getName();
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());
		ACR acr = this.providerMetadata.getACRs().get(0);
		AMR amr = AMR.PWD;
		String sessionId = request.getSessionId();
		State sessionState = (this.providerMetadata.getCheckSessionIframeURI() != null) ? State.parse(sessionId) : null;

		AuthorizationCodeContext context = new AuthorizationCodeContext(principal, clientId, scope, authenticationTime,
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

		String principal = authentication.getName();
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());
		ACR acr = this.providerMetadata.getACRs().get(0);
		AMR amr = AMR.PWD;
		String sessionId = request.getSessionId();
		State sessionState = (this.providerMetadata.getCheckSessionIframeURI() != null) ? State.parse(sessionId) : null;

		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, scope,
					this.accessTokenClaimsMapper);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(principal, client, scope, authenticationTime, acr, amr,
				this.idTokenClaimsMapper, sessionId, nonce, accessToken, null,
				(responseType.size() == 1) ? this.userInfoMapper : null);
		JWT idToken = this.tokenService.createIdToken(idTokenRequest);

		return new AuthenticationSuccessResponse(redirectionUri, null, idToken, accessToken, state, sessionState,
				responseMode);
	}

	private AuthenticationSuccessResponse handleHybridFlow(AuthenticationRequest authRequest,
			OIDCClientInformation client, ServletWebRequest request, Authentication authentication) {
		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientID = authRequest.getClientID();
		URI redirectionURI = authRequest.getRedirectionURI();
		Scope scope = resolveScope(authRequest, client.getOIDCMetadata());
		State state = authRequest.getState();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();

		String principal = authentication.getName();
		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());
		ACR acr = this.providerMetadata.getACRs().get(0);
		AMR amr = AMR.PWD;
		String sessionId = request.getSessionId();
		State sessionState = (this.providerMetadata.getCheckSessionIframeURI() != null) ? State.parse(sessionId) : null;

		AuthorizationCodeContext context = new AuthorizationCodeContext(principal, clientID, scope, authenticationTime,
				acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);
		AuthorizationCode code = this.authorizationCodeService.create(context);
		AccessToken accessToken = null;

		if (responseType.contains(ResponseType.Value.TOKEN)) {
			AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, scope,
					this.accessTokenClaimsMapper);
			accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		}

		JWT idToken = null;

		if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
			IdTokenRequest idTokenRequest = new IdTokenRequest(principal, client, scope, authenticationTime, acr, amr,
					this.idTokenClaimsMapper, sessionId, nonce, accessToken, code, null);
			idToken = this.tokenService.createIdToken(idTokenRequest);
		}

		return new AuthenticationSuccessResponse(redirectionURI, code, idToken, accessToken, state, sessionState,
				responseMode);
	}

	private Scope resolveScope(AuthenticationRequest authRequest, OIDCClientMetadata clientMetadata) {
		Scope requestedScope = authRequest.getScope();
		requestedScope.retainAll(this.providerMetadata.getScopes());
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

	private String prepareResponse(AuthorizationResponse authResponse, Model model) {
		if (ResponseMode.FORM_POST.equals(authResponse.getResponseMode())) {
			model.addAttribute("authResponse", authResponse);

			return FORM_POST_VIEW_NAME;
		}

		return "redirect:" + authResponse.toURI();
	}

	@ExceptionHandler(GeneralException.class)
	public String handleGeneralException(GeneralException e, Model model) {
		AuthenticationErrorResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(),
				e.getErrorObject(), e.getState(), e.getResponseMode());

		return prepareResponse(authResponse, model);
	}

}
