package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

@Controller
@RequestMapping(path = "/authorize")
public class AuthorizationEndpoint {

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	public AuthorizationEndpoint(AuthorizationCodeService authorizationCodeService, TokenService tokenService) {
		this.tokenService = Objects.requireNonNull(tokenService);
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
	}

	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public String authorize(HTTPRequest request, Authentication authentication, HttpSession session) throws Exception {
		AuthorizationRequest authRequest = AuthorizationRequest.parse(request);

		try {
			authRequest = AuthenticationRequest.parse(request);
		}
		catch (ParseException e) {
			Scope scope = authRequest.getScope();

			if (scope != null && scope.contains(OIDCScopeValue.OPENID)) {
				throw e;
			}

			// otherwise still a valid OAuth2 request
		}

		ClientID clientID = authRequest.getClientID();
		// TODO validate client

		URI redirectionURI = authRequest.getRedirectionURI();

		if (redirectionURI == null) {
			// TODO pull from client registration
			redirectionURI = URI.create("http://example.com");
		}

		State state = authRequest.getState();
		ResponseType responseType = authRequest.getResponseType();

		UserDetails principal = (UserDetails) authentication.getPrincipal();

		AuthorizationResponse authResponse;

		// Authorization Code Flow
		if (responseType.impliesCodeFlow()) {
			Map<String, Object> authContext = new HashMap<>();
			authContext.put("authRequest", authRequest);
			authContext.put("authentication", authentication);

			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				AuthorizationCode code = this.authorizationCodeService.create(authContext);
				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
						null);
			}
			// OAuth2 request
			else {
				AuthorizationCode code = this.authorizationCodeService.create(authContext);

				authResponse = new AuthorizationSuccessResponse(redirectionURI, code, null, state, null);
			}
		}
		// Implicit Flow
		else {
			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				JWT idToken = this.tokenService.createIdToken((AuthenticationRequest) authRequest, principal);
				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectionURI, null, idToken, accessToken, state,
						sessionState, null);
			}
			// OAuth2 request
			else {
				AccessToken accessToken = this.tokenService.createAccessToken(authRequest, principal);

				authResponse = new AuthorizationSuccessResponse(redirectionURI, null, accessToken, state, null);
			}
		}

		return "redirect:" + authResponse.toURI();
	}

	@ExceptionHandler(ParseException.class)
	public void handleParseException(ParseException e, HttpServletResponse response) throws Exception {
		if (e.getClientID() == null || e.getRedirectionURI() == null) {
			response.sendError(HttpStatus.BAD_REQUEST.value(), e.getMessage());
		}
		else {
			AuthorizationResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(),
					e.getErrorObject(), e.getState(), e.getResponseMode());
			response.sendRedirect(authResponse.toURI().toString());
		}
	}

}
