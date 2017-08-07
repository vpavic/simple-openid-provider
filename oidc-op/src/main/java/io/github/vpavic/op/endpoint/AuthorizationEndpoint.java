package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Objects;
import java.util.Set;

import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

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
@RequestMapping(path = "/oauth2/authorize")
public class AuthorizationEndpoint {

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	public AuthorizationEndpoint(ClientRepository clientRepository, AuthorizationCodeService authorizationCodeService,
			TokenService tokenService) {
		this.clientRepository = Objects.requireNonNull(clientRepository);
		this.tokenService = Objects.requireNonNull(tokenService);
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
	}

	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public String authorize(HTTPRequest request, Authentication authentication, HttpSession session) throws Exception {
		AuthorizationRequest authRequest = AuthorizationRequest.parse(request);

		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientID = authRequest.getClientID();
		URI redirectURI = authRequest.getRedirectionURI();
		Scope scope = authRequest.getScope();
		State state = authRequest.getState();

		try {
			authRequest = AuthenticationRequest.parse(request);
		}
		catch (ParseException e) {
			if (redirectURI == null) {
				throw new GeneralException("Missing \"redirect_uri\" parameter", OAuth2Error.INVALID_REQUEST, clientID,
						null, responseMode, state, e);
			}

			OIDCClientInformation client = resolveClient(authRequest);
			validateRedirectUri(authRequest, client.getOIDCMetadata());

			if (scope == null) {
				throw new GeneralException("Missing \"scope\" parameter", OAuth2Error.INVALID_REQUEST, clientID,
						redirectURI, responseMode, state, e);
			}

			if (scope.contains(OIDCScopeValue.OPENID)) {
				throw e;
			}

			// otherwise still a valid OAuth2 request
		}

		OIDCClientInformation client = resolveClient(authRequest);
		OIDCClientMetadata clientMetadata = client.getOIDCMetadata();
		validateRedirectUri(authRequest, clientMetadata);
		validateScope(authRequest, clientMetadata);
		validateResponseType(authRequest, clientMetadata);

		UserDetails principal = (UserDetails) authentication.getPrincipal();
		ResponseType responseType = authRequest.getResponseType();

		AuthorizationResponse authResponse;

		// Authorization Code Flow
		if (authRequest.getResponseType().impliesCodeFlow()) {
			AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest, authentication);

			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				AuthorizationCode code = this.authorizationCodeService.create(context);
				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectURI, code, null, null, state, sessionState,
						responseMode);
			}
			// OAuth2 request
			else {
				AuthorizationCode code = this.authorizationCodeService.create(context);

				authResponse = new AuthorizationSuccessResponse(redirectURI, code, null, state, responseMode);
			}
		}
		// Implicit Flow
		else if (!responseType.contains(ResponseType.Value.CODE)) {
			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				JWT idToken = this.tokenService.createIdToken((AuthenticationRequest) authRequest, principal);
				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectURI, null, idToken, accessToken, state,
						sessionState, responseMode);
			}
			// OAuth2 request
			else {
				AccessToken accessToken = this.tokenService.createAccessToken(authRequest, principal);

				authResponse = new AuthorizationSuccessResponse(redirectURI, null, accessToken, state, responseMode);
			}
		}
		// Hybrid Flow
		else {
			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				JWT idToken = null;

				if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
					idToken = this.tokenService.createIdToken((AuthenticationRequest) authRequest, principal);
				}

				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				AuthorizationCode code = this.authorizationCodeService
						.create(new AuthorizationCodeContext(authRequest, authentication));

				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectURI, code, idToken, accessToken, state,
						sessionState, responseMode);
			}
			// OAuth2 request
			else {
				AuthorizationCode code = this.authorizationCodeService
						.create(new AuthorizationCodeContext(authRequest, authentication));

				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				authResponse = new AuthorizationSuccessResponse(redirectURI, code, accessToken, state, responseMode);
			}
		}

		return "redirect:" + authResponse.toURI();
	}

	private OIDCClientInformation resolveClient(AuthorizationRequest authRequest) throws GeneralException {
		OIDCClientInformation client = this.clientRepository.findByClientId(authRequest.getClientID());

		if (client == null) {
			ErrorObject error = OAuth2Error.INVALID_CLIENT;
			throw new GeneralException(error.getDescription(), error, authRequest.getClientID(),
					authRequest.getRedirectionURI(), authRequest.impliedResponseMode(), authRequest.getState());
		}

		return client;
	}

	private void validateRedirectUri(AuthorizationRequest authRequest, OIDCClientMetadata clientMetadata)
			throws GeneralException {
		Set<URI> registeredRedirectionURIs = clientMetadata.getRedirectionURIs();

		if (registeredRedirectionURIs == null || !registeredRedirectionURIs.contains(authRequest.getRedirectionURI())) {
			throw new GeneralException("Mismatching \"redirect_uri\" parameter", OAuth2Error.INVALID_REQUEST,
					authRequest.getClientID(), null, authRequest.impliedResponseMode(), authRequest.getState());
		}
	}

	private void validateScope(AuthorizationRequest authRequest, OIDCClientMetadata clientMetadata)
			throws GeneralException {
		Scope registeredScope = clientMetadata.getScope();

		if (registeredScope == null
				|| !registeredScope.toStringList().containsAll(authRequest.getScope().toStringList())) {
			ErrorObject error = OAuth2Error.INVALID_SCOPE;
			throw new GeneralException(error.getDescription(), error, authRequest.getClientID(),
					authRequest.getRedirectionURI(), authRequest.impliedResponseMode(), authRequest.getState());
		}
	}

	private void validateResponseType(AuthorizationRequest authRequest, OIDCClientMetadata clientMetadata)
			throws GeneralException {
		if (!clientMetadata.getResponseTypes().contains(authRequest.getResponseType())) {
			ErrorObject error = OAuth2Error.UNAUTHORIZED_CLIENT;
			throw new GeneralException(error.getDescription(), error, authRequest.getClientID(),
					authRequest.getRedirectionURI(), authRequest.impliedResponseMode(), authRequest.getState());
		}
	}

	@ExceptionHandler(GeneralException.class)
	public String handleParseException(GeneralException e, ServletWebRequest request, Model model) throws Exception {
		ErrorObject error = e.getErrorObject();

		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST;
		}

		if (e.getClientID() == null || e.getRedirectionURI() == null) {
			if (request.getResponse() != null) {
				request.getResponse().setStatus(error.getHTTPStatusCode());
			}

			model.addAttribute("code", error.getCode());
			model.addAttribute("description", e.getMessage());
			return "error";
		}
		else {
			AuthorizationResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), error,
					e.getState(), e.getResponseMode());
			return "redirect:" + authResponse.toURI();
		}
	}

}
