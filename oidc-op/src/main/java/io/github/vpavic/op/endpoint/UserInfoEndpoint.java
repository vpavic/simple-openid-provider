package io.github.vpavic.op.endpoint;

import java.security.Principal;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/userinfo")
public class UserInfoEndpoint {

	@CrossOrigin
	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public void getUserInfo(Principal principal, HttpServletResponse response) throws Exception {
		UserInfo userInfo = new UserInfo(new Subject(principal.getName()));
		UserInfoSuccessResponse userInfoResponse = new UserInfoSuccessResponse(userInfo);
		ServletUtils.applyHTTPResponse(userInfoResponse.toHTTPResponse(), response);
	}

}
