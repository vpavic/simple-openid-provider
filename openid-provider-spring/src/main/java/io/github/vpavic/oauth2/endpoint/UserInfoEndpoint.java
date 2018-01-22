package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(path = UserInfoEndpoint.PATH_MAPPING)
public class UserInfoEndpoint {

	public static final String PATH_MAPPING = "/oauth2/userinfo";

	private final UserInfoHandler handler;

	public UserInfoEndpoint(UserInfoHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public void getUserInfo(HttpServletRequest request, HttpServletResponse response) throws IOException {
		this.handler.getUserInfo(request, response);
	}

}
