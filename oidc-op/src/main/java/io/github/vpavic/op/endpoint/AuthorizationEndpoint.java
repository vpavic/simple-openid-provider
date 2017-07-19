package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.springframework.stereotype.Controller;
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
	public void authorize(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse;

		try {
			AuthenticationRequest authRequest = AuthenticationRequest.parse(httpRequest);

			ClientID clientID = authRequest.getClientID();
			// TODO validate client

			URI redirectionURI = authRequest.getRedirectionURI();
			State state = authRequest.getState();

			Tokens tokens = this.tokenService.createTokens(authRequest, request.getUserPrincipal());

			// Authorization Code Flow
			if (authRequest.getResponseType().impliesCodeFlow()) {
				AuthorizationCode code = this.authorizationCodeService.create(tokens);
				State sessionState = State.parse(request.getSession().getId());
				ResponseMode responseMode = ResponseMode.QUERY;

				httpResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
						responseMode).toHTTPResponse();
			}
			// TODO Implicit Flow
			else {
				throw new UnsupportedOperationException();
			}
		}
		catch (ParseException e) {
			if (e.getClientID() == null || e.getRedirectionURI() == null) {
				httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
			}
			else {
				httpResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), e.getErrorObject(), e.getState(),
						e.getResponseMode()).toHTTPResponse();
			}
		}

		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

}
