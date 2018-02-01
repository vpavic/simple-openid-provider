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
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import io.github.vpavic.oauth2.authentication.AccessTokenClaimsResolver;
import io.github.vpavic.oauth2.claim.ClaimHelper;
import io.github.vpavic.oauth2.claim.ClaimSource;

/**
 * OpenID Connect 1.0 compatible UserInfo Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
public class UserInfoHandler {

	private final AccessTokenClaimsResolver accessTokenClaimsResolver;

	private final ClaimSource claimSource;

	private String accessTokenScopeClaim = "scp";

	private Map<Scope.Value, List<String>> scopeClaims = new HashMap<>();

	public UserInfoHandler(AccessTokenClaimsResolver accessTokenClaimsResolver, ClaimSource claimSource) {
		Objects.requireNonNull(accessTokenClaimsResolver, "accessTokenClaimsResolver must not be null");
		Objects.requireNonNull(claimSource, "claimSource must not be null");
		this.accessTokenClaimsResolver = accessTokenClaimsResolver;
		this.claimSource = claimSource;
	}

	public void setAccessTokenScopeClaim(String accessTokenScopeClaim) {
		this.accessTokenScopeClaim = accessTokenScopeClaim;
	}

	public void setScopeClaims(Map<Scope.Value, List<String>> scopeClaims) {
		this.scopeClaims = scopeClaims;
	}

	@SuppressWarnings("unchecked")
	public HTTPResponse getUserInfo(HTTPRequest httpRequest) {
		HTTPResponse httpResponse;

		try {
			UserInfoRequest userInfoRequest = UserInfoRequest.parse(httpRequest);
			AccessToken accessToken = userInfoRequest.getAccessToken();

			Map<String, Object> accessTokenClaims = this.accessTokenClaimsResolver.resolveClaims(accessToken);
			Subject subject = new Subject((String) accessTokenClaims.get("sub"));
			Scope scope = Scope.parse((List<String>) accessTokenClaims.get(this.accessTokenScopeClaim));
			Set<String> claims = ClaimHelper.resolveClaims(scope, this.scopeClaims);
			UserInfo userInfo = this.claimSource.load(subject, claims);

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
