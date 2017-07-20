package io.github.vpavic.op.endpoint;

import java.util.Objects;

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
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
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
	public JSONObject handleTokenRequest(HTTPRequest request) throws Exception {
		TokenRequest tokenRequest = TokenRequest.parse(request);

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
				return new OIDCTokenResponse((OIDCTokens) tokens).toJSONObject();
			}

			return new AccessTokenResponse(tokens).toJSONObject();
		}

		return new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toJSONObject();
	}

	@ExceptionHandler(ParseException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public JSONObject handleParseException(ParseException e) {
		ErrorObject error = e.getErrorObject();
		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage());
		}
		return new TokenErrorResponse(error).toJSONObject();
	}

}
