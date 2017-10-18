package io.github.vpavic.op.oauth2.userinfo;

import java.util.Objects;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * OpenID Connect 1.0 compatible UserInfo Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@RestController
@RequestMapping(path = UserInfoEndpoint.PATH_MAPPING)
public class UserInfoEndpoint {

	public static final String PATH_MAPPING = "/oauth2/userinfo";

	private static final String SCOPE_CLAIM = "scope";

	private final UserInfoMapper userInfoMapper;

	public UserInfoEndpoint(UserInfoMapper userInfoMapper) {
		Objects.requireNonNull(userInfoMapper, "userInfoMapper must not be null");

		this.userInfoMapper = userInfoMapper;
	}

	@CrossOrigin
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public ResponseEntity<String> getUserInfo(Authentication authentication) throws Exception {
		String principal = authentication.getName();
		JWTClaimsSet claimsSet = (JWTClaimsSet) authentication.getDetails();
		Scope scope = Scope.parse(claimsSet.getStringClaim(SCOPE_CLAIM));
		UserInfo userInfo = this.userInfoMapper.map(principal, scope);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(userInfo.toJSONObject().toJSONString());
		// @formatter:on
	}

}
