package io.github.vpavic.op.endpoint;

import java.util.Objects;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.github.vpavic.op.userinfo.ClaimsMapper;

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

	private final ClaimsMapper claimsMapper;

	public UserInfoEndpoint(ClaimsMapper claimsMapper) {
		this.claimsMapper = Objects.requireNonNull(claimsMapper);
	}

	@CrossOrigin
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public JSONObject getUserInfo(Authentication authentication) throws Exception {
		JWTClaimsSet claims = (JWTClaimsSet) authentication.getDetails();
		UserInfo userInfo = new UserInfo(new Subject(claims.getSubject()));
		this.claimsMapper.map(userInfo, new Scope(claims.getStringClaim(SCOPE_CLAIM)));

		return userInfo.toJSONObject();
	}

}
