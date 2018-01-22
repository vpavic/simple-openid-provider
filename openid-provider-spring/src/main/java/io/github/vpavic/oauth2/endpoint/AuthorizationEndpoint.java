package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = AuthorizationEndpoint.PATH_MAPPING)
public class AuthorizationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/authorize";

	private final AuthorizationHandler handler;

	public AuthorizationEndpoint(AuthorizationHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void authorize(HttpServletRequest request, HttpServletResponse response) throws IOException {
		this.handler.authorize(request, response);
	}

}
