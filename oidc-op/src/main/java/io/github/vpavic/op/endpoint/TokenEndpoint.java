package io.github.vpavic.op.endpoint;

import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.vpavic.op.code.AuthorizationCodeService;

@RestController
@RequestMapping(path = "/token")
public class TokenEndpoint {

	private final AuthorizationCodeService authorizationCodeService;

	public TokenEndpoint(AuthorizationCodeService authorizationCodeService) {
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
	}

	@PostMapping
	public void handleTokenRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse;

		try {
			TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

			ClientID clientID = tokenRequest.getClientID();
			// TODO validate client

			AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();

			// Authorization Code Grant Type
			if (authorizationGrant instanceof AuthorizationCodeGrant) {
				AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;
				Tokens tokens = this.authorizationCodeService.consume(authorizationCodeGrant.getAuthorizationCode());

				if (tokens == null) {
					throw new GeneralException(new ErrorObject("invalid_request"));
				}

				if (tokens instanceof OIDCTokens) {
					httpResponse = new OIDCTokenResponse((OIDCTokens) tokens).toHTTPResponse();
				}
				else {
					httpResponse = new AccessTokenResponse(tokens).toHTTPResponse();
				}
			}
			else {
				httpResponse = new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse();
			}
		}
		catch (ParseException e) {
			ErrorObject error = e.getErrorObject();
			if (error == null) {
				error = OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage());
			}
			httpResponse = new TokenErrorResponse(error).toHTTPResponse();
		}

		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

}
