package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.security.Principal;
import java.util.Objects;

import javax.servlet.http.HttpSession;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.ServletWebRequest;

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

		Tokens tokens = this.tokenService.createTokens(authRequest, principal);

		// Authorization Code Flow
		if (authRequest.getResponseType().impliesCodeFlow()) {
			AuthorizationCode code = this.authorizationCodeService.create(tokens);
			State sessionState = State.parse(session.getId());
			ResponseMode responseMode = ResponseMode.QUERY;

			AuthorizationResponse authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null,
					state, sessionState, responseMode);
			return "redirect:" + authResponse.toURI();
		}
		// TODO Implicit Flow
		else {
			throw new UnsupportedOperationException();
		}
	}

	@ExceptionHandler(ParseException.class)
	public String handleParseException(ParseException e, ServletWebRequest request) {
		if (e.getClientID() == null || e.getRedirectionURI() == null) {
			request.getResponse().setStatus(HttpStatus.BAD_REQUEST.value());
			return e.getMessage();
		}
		AuthorizationResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), e.getErrorObject(),
				e.getState(), e.getResponseMode());
		return "redirect:" + authResponse.getRedirectionURI();
	}

}
