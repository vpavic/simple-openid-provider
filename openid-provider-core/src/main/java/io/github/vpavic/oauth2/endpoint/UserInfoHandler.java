package io.github.vpavic.oauth2.endpoint;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import io.github.vpavic.oauth2.claim.ClaimHelper;
import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.token.AccessTokenContext;
import io.github.vpavic.oauth2.token.AccessTokenService;

/**
 * OpenID Connect 1.0 compatible UserInfo Endpoint implementation.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
public class UserInfoHandler {

	private final AccessTokenService accessTokenService;

	private final ClaimSource claimSource;

	private Map<Scope.Value, List<String>> scopeClaims = new HashMap<>();

	public UserInfoHandler(AccessTokenService accessTokenService, ClaimSource claimSource) {
		Objects.requireNonNull(accessTokenService, "accessTokenService must not be null");
		Objects.requireNonNull(claimSource, "claimSource must not be null");
		this.accessTokenService = accessTokenService;
		this.claimSource = claimSource;
	}

	public void setScopeClaims(Map<Scope.Value, List<String>> scopeClaims) {
		this.scopeClaims = scopeClaims;
	}

	public HTTPResponse getUserInfo(HTTPRequest httpRequest) {
		HTTPResponse httpResponse;

		try {
			UserInfoRequest userInfoRequest = UserInfoRequest.parse(httpRequest);
			AccessToken accessToken = userInfoRequest.getAccessToken();

			AccessTokenContext accessTokenContext = this.accessTokenService.resolveAccessTokenContext(accessToken);
			Scope scope = accessTokenContext.getScope();
			if (scope.isEmpty() || !scope.contains(OIDCScopeValue.OPENID.getValue())) {
				throw new GeneralException(BearerTokenError.INSUFFICIENT_SCOPE);
			}
			Set<String> claims = ClaimHelper.resolveClaims(scope, this.scopeClaims);
			UserInfo userInfo = this.claimSource.load(accessTokenContext.getSubject(), claims);

			UserInfoSuccessResponse userInfoResponse = new UserInfoSuccessResponse(userInfo);
			httpResponse = userInfoResponse.toHTTPResponse();
		}
		catch (GeneralException e) {
			UserInfoErrorResponse userInfoResponse = new UserInfoErrorResponse(e.getErrorObject());
			httpResponse = userInfoResponse.toHTTPResponse();
		}

		httpRequest.setHeader("Access-Control-Allow-Origin", "*");
		httpRequest.setHeader("Access-Control-Allow-Methods", "GET, POST");
		return httpResponse;
	}

}
