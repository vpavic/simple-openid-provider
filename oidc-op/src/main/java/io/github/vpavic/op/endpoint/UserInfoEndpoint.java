package io.github.vpavic.op.endpoint;

import java.util.Objects;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.github.vpavic.op.userinfo.UserInfoMapper;

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
		this.userInfoMapper = Objects.requireNonNull(userInfoMapper);
	}

	@CrossOrigin
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public JSONObject getUserInfo(Authentication authentication) throws Exception {
		String principal = authentication.getName();
		JWTClaimsSet claimsSet = (JWTClaimsSet) authentication.getDetails();
		Scope scope = new Scope(claimsSet.getStringClaim(SCOPE_CLAIM));
		UserInfo userInfo = this.userInfoMapper.map(principal, scope);

		return userInfo.toJSONObject();
	}

}
