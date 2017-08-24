package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.security.web.authentication.OpenIdWebAuthenticationDetails;
import io.github.vpavic.op.token.ClaimsMapper;
import io.github.vpavic.op.token.TokenService;
import io.github.vpavic.op.userinfo.UserInfoMapper;

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

	private static final String LOGIN_URL = "/login";

	private static final String ERROR_VIEW_NAME = "error";

	private static final RequestCache requestCache = new HttpSessionRequestCache();

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final ClaimsMapper claimsMapper;

	private final UserInfoMapper userInfoMapper;

	public AuthorizationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository,
			AuthorizationCodeService authorizationCodeService, TokenService tokenService, ClaimsMapper claimsMapper,
			UserInfoMapper userInfoMapper) {
		this.properties = properties;
		this.clientRepository = Objects.requireNonNull(clientRepository);
		this.tokenService = Objects.requireNonNull(tokenService);
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
		this.claimsMapper = Objects.requireNonNull(claimsMapper);
		this.userInfoMapper = Objects.requireNonNull(userInfoMapper);
	}

	@GetMapping
	public View authorize(HttpServletRequest request, Authentication authentication) throws Exception {
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
			requestCache.saveRequest(request, null);

			return new RedirectView(LOGIN_URL);
		}

		String principal = authentication.getName();
		OpenIdWebAuthenticationDetails authenticationDetails = (OpenIdWebAuthenticationDetails) authentication.getDetails();
		Instant authenticationTime = authenticationDetails.getAuthenticationTime();
		String sessionId = request.getSession().getId();
		State sessionState = this.properties.isSessionManagementEnabled() ? State.parse(sessionId) : null;

		if (maxAge > 0 && authenticationTime.plusSeconds(maxAge).isBefore(Instant.now())) {
			requestCache.saveRequest(request, null);

			return new RedirectView(LOGIN_URL);
		}

		AuthenticationSuccessResponse authResponse;

		// Authorization Code Flow
		if (responseType.impliesCodeFlow()) {
			AuthorizationCodeContext context = new AuthorizationCodeContext(principal, clientID, scope,
					authenticationTime, sessionId, codeChallenge, codeChallengeMethod, nonce);

			AuthorizationCode code = this.authorizationCodeService.create(context);

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
					responseMode);
		}
		// Implicit Flow
		else if (!responseType.contains(ResponseType.Value.CODE)) {
			UserInfoMapper userInfoMapper = (responseType.size() == 1) ? this.userInfoMapper : null;

			JWT idToken = this.tokenService.createIdToken(principal, clientID, scope, authenticationTime, sessionId,
					nonce, userInfoMapper);
			AccessToken accessToken = null;

			if (responseType.contains(ResponseType.Value.TOKEN)) {
				accessToken = this.tokenService.createAccessToken(principal, clientID, scope, this.claimsMapper);
			}

			authResponse = new AuthenticationSuccessResponse(redirectionURI, null, idToken, accessToken, state,
					sessionState, responseMode);
		}
		// Hybrid Flow
		else {
			AuthorizationCodeContext context = new AuthorizationCodeContext(principal, clientID, scope,
					authenticationTime, sessionId, codeChallenge, codeChallengeMethod, nonce);

			JWT idToken = null;

			if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
				idToken = this.tokenService.createIdToken(principal, clientID, scope, authenticationTime, sessionId,
						nonce, null);
			}

			AccessToken accessToken = null;

			if (responseType.contains(ResponseType.Value.TOKEN)) {
				accessToken = this.tokenService.createAccessToken(principal, clientID, scope, this.claimsMapper);
			}

			AuthorizationCode code = this.authorizationCodeService.create(context);

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, idToken, accessToken, state,
					sessionState, responseMode);
		}

		return new RedirectView(authResponse.toURI().toString());
	}

	private AuthenticationRequest resolveRequest(HttpServletRequest request, Authentication authentication)
			throws GeneralException {
		AuthenticationRequest authRequest = AuthenticationRequest.parse(request.getQueryString());
		validateRequest(authRequest, authentication);

		return authRequest;
	}

	private void validateRequest(AuthenticationRequest request, Authentication authentication) throws GeneralException {
		ResponseType responseType = request.getResponseType();
		ClientID clientID = request.getClientID();
		URI redirectionURI = request.getRedirectionURI();
		Scope scope = request.getScope();
		Prompt prompt = request.getPrompt();

		OIDCClientInformation client = this.clientRepository.findByClientId(clientID);

		if (client == null) {
			throw new GeneralException(
					OAuth2Error.INVALID_REQUEST.setDescription("Invalid \"client_id\" parameter: " + clientID));
		}

		OIDCClientMetadata clientMetadata = client.getOIDCMetadata();

		Set<URI> registeredRedirectionURIs = clientMetadata.getRedirectionURIs();

		if (registeredRedirectionURIs == null || !registeredRedirectionURIs.contains(redirectionURI)) {
			throw new GeneralException(OAuth2Error.INVALID_REQUEST
					.setDescription("Invalid \"redirect_uri\" parameter: " + redirectionURI));
		}

		Scope registeredScope = clientMetadata.getScope();

		if (registeredScope == null || !registeredScope.toStringList().containsAll(scope.toStringList())) {
			throw new GeneralException(OAuth2Error.INVALID_SCOPE);
		}

		if (!clientMetadata.getResponseTypes().contains(responseType)) {
			throw new GeneralException(OAuth2Error.UNAUTHORIZED_CLIENT);
		}

		if (prompt != null && prompt.contains(Prompt.Type.NONE) && authentication == null) {
			throw new GeneralException(OIDCError.LOGIN_REQUIRED);
		}
	}

	@ExceptionHandler(GeneralException.class)
	public ModelAndView handleGeneralException(GeneralException e) {
		ModelMap model = new ModelMap();
		model.addAttribute("timestamp", new Date());

		ErrorObject error = e.getErrorObject();

		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST;
		}

		model.addAttribute("status", error.getHTTPStatusCode());
		model.addAttribute("error", error.getCode());
		model.addAttribute("message", e.getMessage());

		return new ModelAndView(ERROR_VIEW_NAME, model, HttpStatus.valueOf(error.getHTTPStatusCode()));
	}

}
