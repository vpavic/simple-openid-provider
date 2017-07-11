package io.github.vpavic;

import java.util.Objects;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
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

@RestController
@RequestMapping(path = "/token")
public class TokenEndpoint {

	private final ConcurrentMap<String, Tokens> tokenStore;

	public TokenEndpoint(ConcurrentMap<String, Tokens> tokenStore) {
		this.tokenStore = Objects.requireNonNull(tokenStore);
	}

	@PostMapping
	public JSONObject handleTokenRequest(HttpServletRequest request) throws Exception {
		TokenRequest tokenRequest = TokenRequest.parse(ServletUtils.createHTTPRequest(request));
		AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
		// Authorization Code Grant Type
		if (authorizationGrant instanceof AuthorizationCodeGrant) {
			AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;
			AuthorizationCode authorizationCode = authorizationCodeGrant.getAuthorizationCode();
			Tokens tokens = this.tokenStore.remove(authorizationCode.getValue());
			if (tokens == null) {
				throw new GeneralException(new ErrorObject("invalid_request"));
			}
			if (tokens instanceof OIDCTokens) {
				return new OIDCTokenResponse((OIDCTokens) tokens).toJSONObject();
			}
			return new AccessTokenResponse(tokens).toJSONObject();
		}
		// TODO Resource Owner Password Credentials Grant Type
		else if (authorizationGrant instanceof ResourceOwnerPasswordCredentialsGrant) {
			throw new GeneralException(new ErrorObject("not_yet_implemented"));
		}
		// TODO Client Credentials Grant Type
		else if (authorizationGrant instanceof ClientCredentialsGrant) {
			throw new GeneralException(new ErrorObject("not_yet_implemented"));
		}
		// TODO Refresh Token Grant Type
		else if (authorizationGrant instanceof RefreshTokenGrant) {
			throw new GeneralException(new ErrorObject("not_yet_implemented"));
		}
		throw new GeneralException(new ErrorObject("not_yet_implemented"));
	}

	@ExceptionHandler(GeneralException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public JSONObject handleError(GeneralException e) {
		return new TokenErrorResponse(e.getErrorObject()).toJSONObject();
	}

}
