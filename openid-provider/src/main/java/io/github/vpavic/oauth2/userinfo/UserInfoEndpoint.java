package io.github.vpavic.oauth2.userinfo;

import java.util.Objects;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import io.github.vpavic.oauth2.claim.UserClaimsLoader;

/**
 * OpenID Connect 1.0 compatible UserInfo Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@RequestMapping(path = UserInfoEndpoint.PATH_MAPPING)
public class UserInfoEndpoint {

	public static final String PATH_MAPPING = "/oauth2/userinfo";

	private static final String SCOPE_CLAIM = "scope";

	private final UserClaimsLoader userClaimsLoader;

	public UserInfoEndpoint(UserClaimsLoader userClaimsLoader) {
		Objects.requireNonNull(userClaimsLoader, "userClaimsLoader must not be null");

		this.userClaimsLoader = userClaimsLoader;
	}

	@CrossOrigin
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public ResponseEntity<String> getUserInfo(Authentication authentication) throws Exception {
		JWTClaimsSet claimsSet = (JWTClaimsSet) authentication.getDetails();

		Subject subject = new Subject(claimsSet.getSubject());
		Scope scope = Scope.parse(claimsSet.getStringListClaim(SCOPE_CLAIM));
		UserInfo userInfo = this.userClaimsLoader.load(subject, scope);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(userInfo.toJSONObject().toJSONString());
		// @formatter:on
	}

}
