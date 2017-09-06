package io.github.vpavic.op.oauth2.endpoint;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;

import io.github.vpavic.op.config.OpenIdProviderProperties;
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

	private static final String ERROR_VIEW_NAME = "error";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final UserInfoMapper userInfoMapper;

	public AuthorizationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository,
			AuthorizationCodeService authorizationCodeService, TokenService tokenService,
			AccessTokenClaimsMapper accessTokenClaimsMapper, IdTokenClaimsMapper idTokenClaimsMapper,
			UserInfoMapper userInfoMapper) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		Objects.requireNonNull(accessTokenClaimsMapper, "accessTokenClaimsMapper must not be null");
		Objects.requireNonNull(idTokenClaimsMapper, "idTokenClaimsMapper must not be null");
		Objects.requireNonNull(userInfoMapper, "userInfoMapper must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
		this.tokenService = tokenService;
		this.authorizationCodeService = authorizationCodeService;
		this.accessTokenClaimsMapper = accessTokenClaimsMapper;
		this.idTokenClaimsMapper = idTokenClaimsMapper;
		this.userInfoMapper = userInfoMapper;
	}

	@GetMapping
	public ModelAndView authorize(ServletWebRequest request, Authentication authentication) throws Exception {
		AuthenticationRequest authRequest = resolveRequest(request, authentication);

		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientID = authRequest.getClientID();
		URI redirectionURI = authRequest.getRedirectionURI();
		Scope scope = authRequest.getScope();
		State state = authRequest.getState();
		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();
		Prompt prompt = authRequest.getPrompt();
		int maxAge = authRequest.getMaxAge();

		if (authentication == null || (prompt != null && prompt.contains(Prompt.Type.LOGIN))) {
			return redirectToLoginPage(request, authRequest);
		}

		Instant authenticationTime = Instant.ofEpochMilli(request.getRequest().getSession().getCreationTime());

		if (maxAge > 0 && authenticationTime.plusSeconds(maxAge).isBefore(Instant.now())) {
			return redirectToLoginPage(request, authRequest);
		}

		request.removeAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE, RequestAttributes.SCOPE_SESSION);

		String principal = authentication.getName();
		ACR acr = new ACR(this.properties.getAuthorization().getAcrs().get(0));
		AMR amr = AMR.PWD;
		String sessionId = request.getSessionId();
		State sessionState = this.properties.getSessionManagement().isEnabled() ? State.parse(sessionId) : null;

		AuthenticationSuccessResponse authResponse;

		// Authorization Code Flow
		if (responseType.impliesCodeFlow()) {
			AuthorizationCodeContext context = new AuthorizationCodeContext(principal, clientID, scope,
					authenticationTime, acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);

			AuthorizationCode code = this.authorizationCodeService.create(context);

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
					responseMode);
		}
		// Implicit Flow
		else if (!responseType.contains(ResponseType.Value.CODE)) {
			AccessToken accessToken = null;

			if (responseType.contains(ResponseType.Value.TOKEN)) {
				AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, scope,
						this.accessTokenClaimsMapper);
				accessToken = this.tokenService.createAccessToken(accessTokenRequest);
			}

			IdTokenRequest idTokenRequest = new IdTokenRequest(principal, clientID, scope, authenticationTime, acr, amr,
					this.idTokenClaimsMapper, sessionId, nonce, accessToken, null,
					(responseType.size() == 1) ? this.userInfoMapper : null);
			JWT idToken = this.tokenService.createIdToken(idTokenRequest);

			authResponse = new AuthenticationSuccessResponse(redirectionURI, null, idToken, accessToken, state,
					sessionState, responseMode);
		}
		// Hybrid Flow
		else {
			AuthorizationCodeContext context = new AuthorizationCodeContext(principal, clientID, scope,
					authenticationTime, acr, amr, sessionId, codeChallenge, codeChallengeMethod, nonce);

			AuthorizationCode code = this.authorizationCodeService.create(context);

			AccessToken accessToken = null;

			if (responseType.contains(ResponseType.Value.TOKEN)) {
				AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, scope,
						this.accessTokenClaimsMapper);
				accessToken = this.tokenService.createAccessToken(accessTokenRequest);
			}

			JWT idToken = null;

			if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
				IdTokenRequest idTokenRequest = new IdTokenRequest(principal, clientID, scope, authenticationTime, acr,
						amr, this.idTokenClaimsMapper, sessionId, nonce, accessToken, code, null);
				idToken = this.tokenService.createIdToken(idTokenRequest);
			}

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, idToken, accessToken, state,
					sessionState, responseMode);
		}

		ModelAndView modelAndView;

		if (!responseMode.equals(ResponseMode.FORM_POST)) {
			modelAndView = new ModelAndView("redirect:" + authResponse.toURI());
		}
		else {
			ModelMap model = new ModelMap("authResponse", authResponse);
			modelAndView = new ModelAndView(FORM_POST_VIEW_NAME, model);
		}

		return modelAndView;
	}

	private AuthenticationRequest resolveRequest(ServletWebRequest request, Authentication authentication)
			throws GeneralException {
		AuthenticationRequest authRequest;

		try {
			authRequest = AuthenticationRequest.parse(request.getRequest().getQueryString());
		}
		catch (ParseException e) {
			ClientID clientID = e.getClientID();
			URI redirectionURI = e.getRedirectionURI();

			if (clientID != null && redirectionURI != null) {
				OIDCClientInformation client = resolveClient(clientID);
				validateRedirectionURI(redirectionURI, client);
			}

			throw e;
		}

		validateRequest(authRequest, authentication);

		return authRequest;
	}

	private OIDCClientInformation resolveClient(ClientID clientID) throws GeneralException {
		OIDCClientInformation client = this.clientRepository.findByClientId(clientID);

		if (client == null) {
			throw new GeneralException(
					OAuth2Error.INVALID_REQUEST.setDescription("Invalid \"client_id\" parameter: " + clientID));
		}

		return client;
	}

	private void validateRedirectionURI(URI redirectionURI, OIDCClientInformation client) throws GeneralException {
		Set<URI> registeredRedirectionURIs = client.getOIDCMetadata().getRedirectionURIs();

		if (registeredRedirectionURIs == null || !registeredRedirectionURIs.contains(redirectionURI)) {
			throw new GeneralException(OAuth2Error.INVALID_REQUEST
					.setDescription("Invalid \"redirect_uri\" parameter: " + redirectionURI));
		}
	}

	private void validateRequest(AuthenticationRequest request, Authentication authentication) throws GeneralException {
		ResponseType responseType = request.getResponseType();
		ResponseMode responseMode = request.impliedResponseMode();
		ClientID clientID = request.getClientID();
		URI redirectionURI = request.getRedirectionURI();
		Scope scope = request.getScope();
		State state = request.getState();
		Prompt prompt = request.getPrompt();

		OIDCClientInformation client = resolveClient(clientID);
		validateRedirectionURI(redirectionURI, client);
		OIDCClientMetadata clientMetadata = client.getOIDCMetadata();

		Scope registeredScope = clientMetadata.getScope();

		if (registeredScope == null || !registeredScope.toStringList().containsAll(scope.toStringList())) {
			ErrorObject error = OAuth2Error.INVALID_SCOPE;
			throw new GeneralException(error.getDescription(), error, clientID, redirectionURI, responseMode, state);
		}

		if (!clientMetadata.getResponseTypes().contains(responseType)) {
			ErrorObject error = OAuth2Error.UNAUTHORIZED_CLIENT;
			throw new GeneralException(error.getDescription(), error, clientID, redirectionURI, responseMode, state);
		}

		if (prompt != null && prompt.contains(Prompt.Type.NONE) && authentication == null) {
			ErrorObject error = OIDCError.LOGIN_REQUIRED;
			throw new GeneralException(error.getDescription(), error, clientID, redirectionURI, responseMode, state);
		}
	}

	private ModelAndView redirectToLoginPage(ServletWebRequest request, AuthenticationRequest authRequest) {
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

	@ExceptionHandler(GeneralException.class)
	public ModelAndView handleGeneralException(GeneralException e) {
		URI redirectionURI = e.getRedirectionURI();

		if (redirectionURI == null) {
			ErrorObject error = e.getErrorObject();

			if (error == null) {
				error = OAuth2Error.INVALID_REQUEST;
			}

			ModelMap model = new ModelMap();
			model.addAttribute("timestamp", new Date());
			model.addAttribute("status", error.getHTTPStatusCode());
			model.addAttribute("error", error.getCode());
			model.addAttribute("message", e.getMessage());

			return new ModelAndView(ERROR_VIEW_NAME, model, HttpStatus.valueOf(error.getHTTPStatusCode()));
		}
		else {
			AuthenticationErrorResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(),
					e.getErrorObject(), e.getState(), e.getResponseMode());

			return new ModelAndView("redirect:" + authResponse.toURI());
		}
	}

}
