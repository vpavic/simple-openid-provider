package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Objects;
import java.util.Set;

import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

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

	@GetMapping
	public String authorize(HTTPRequest request, Authentication authentication, HttpSession session) throws Exception {
		AuthenticationRequest authRequest = AuthenticationRequest.parse(request);

		ResponseType responseType = authRequest.getResponseType();
		ResponseMode responseMode = authRequest.impliedResponseMode();
		ClientID clientID = authRequest.getClientID();
		URI redirectionURI = authRequest.getRedirectionURI();
		Scope scope = authRequest.getScope();
		State state = authRequest.getState();

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

		CodeChallenge codeChallenge = authRequest.getCodeChallenge();
		CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();
		Nonce nonce = authRequest.getNonce();
		UserDetails principal = (UserDetails) authentication.getPrincipal();

		AuthenticationSuccessResponse authResponse;

		// Authorization Code Flow
		if (responseType.impliesCodeFlow()) {
			AuthorizationCodeContext context = new AuthorizationCodeContext(authentication, clientID, scope,
					codeChallenge, codeChallengeMethod, nonce);

			AuthorizationCode code = this.authorizationCodeService.create(context);
			State sessionState = State.parse(session.getId());

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
					responseMode);
		}
		// Implicit Flow
		else if (!responseType.contains(ResponseType.Value.CODE)) {
			JWT idToken = this.tokenService.createIdToken(principal, clientID, scope, nonce);
			AccessToken accessToken = null;

			if (responseType.contains(ResponseType.Value.TOKEN)) {
				accessToken = this.tokenService.createAccessToken(principal, clientID, scope);
			}

			State sessionState = State.parse(session.getId());

			authResponse = new AuthenticationSuccessResponse(redirectionURI, null, idToken, accessToken, state,
					sessionState, responseMode);
		}
		// Hybrid Flow
		else {
			AuthorizationCodeContext context = new AuthorizationCodeContext(authentication, clientID, scope,
					codeChallenge, codeChallengeMethod, nonce);

			JWT idToken = null;

			if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
				idToken = this.tokenService.createIdToken(principal, clientID, scope, nonce);
			}

			AccessToken accessToken = null;

			if (responseType.contains(ResponseType.Value.TOKEN)) {
				accessToken = this.tokenService.createAccessToken(principal, clientID, scope);
			}

			AuthorizationCode code = this.authorizationCodeService.create(context);

			State sessionState = State.parse(session.getId());

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, idToken, accessToken, state,
					sessionState, responseMode);
		}

		return "redirect:" + authResponse.toURI();
	}

	@ExceptionHandler(GeneralException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String handleGeneralException(GeneralException e, Model model) {
		ErrorObject error = e.getErrorObject();

		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST;
		}

		model.addAttribute("code", error.getCode());
		model.addAttribute("description", e.getMessage());
		return "error";
	}

}
