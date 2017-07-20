package io.github.vpavic.op.endpoint;

import java.security.Principal;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/userinfo")
public class UserInfoEndpoint {

	@CrossOrigin
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public JSONObject getUserInfo(Principal principal) throws Exception {
		UserInfo userInfo = new UserInfo(new Subject(principal.getName()));
		return userInfo.toJSONObject();
	}

}
