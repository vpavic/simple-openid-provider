package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = JwkSetEndpoint.PATH_MAPPING)
public class JwkSetEndpoint {

	public static final String PATH_MAPPING = "/oauth2/keys";

	private final JwkSetHandler handler;

	public JwkSetEndpoint(JwkSetHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void getJwkSet(HttpServletResponse response) throws IOException {
		this.handler.getJwkSet(response);
	}

}
