package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.security.Principal;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

@Controller
@RequestMapping(path = "/authorize")
public class AuthorizationEndpoint {

	private final TokenService tokenService;

	private final AuthorizationCodeService authorizationCodeService;

	public AuthorizationEndpoint(TokenService tokenService, AuthorizationCodeService authorizationCodeService)
			throws Exception {
		this.tokenService = Objects.requireNonNull(tokenService);
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
	}

	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public String authorize(HTTPRequest request, Principal principal, HttpSession session) throws Exception {
		AuthenticationRequest authRequest = AuthenticationRequest.parse(request);

		ClientID clientID = authRequest.getClientID();
		// TODO validate client

		URI redirectionURI = authRequest.getRedirectionURI();
		State state = authRequest.getState();
		State sessionState = State.parse(session.getId());
		ResponseType responseType = authRequest.getResponseType();

		AuthorizationResponse authResponse;

		// Authorization Code Flow
		if (responseType.impliesCodeFlow()) {
			AccessToken accessToken = this.tokenService.createAccessToken(authRequest, principal);
			RefreshToken refreshToken = this.tokenService.createRefreshToken();
			JWT idToken = this.tokenService.createIdToken(authRequest, principal);
			OIDCTokens tokens = new OIDCTokens(idToken.serialize(), accessToken, refreshToken);
			AuthorizationCode code = this.authorizationCodeService.create(tokens);

			authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
					null);
		}
		// Implicit Flow
		else {
			AccessToken accessToken = null;
			if (responseType.contains(ResponseType.Value.TOKEN)) {
				accessToken = this.tokenService.createAccessToken(authRequest, principal);
			}
			JWT idToken = null;
			if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
				idToken = this.tokenService.createIdToken(authRequest, principal);
			}
			authResponse = new AuthenticationSuccessResponse(redirectionURI, null, idToken, accessToken, state,
					sessionState, null);
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
