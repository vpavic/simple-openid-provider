package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = EndSessionEndpoint.PATH_MAPPING)
public class EndSessionEndpoint {

	public static final String PATH_MAPPING = "/oauth2/logout";

	private final EndSessionHandler handler;

	public EndSessionEndpoint(EndSessionHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void getLogoutPrompt(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		this.handler.getLogoutPrompt(request, response);
	}

	@PostMapping
	public void handleLogoutSuccess(HttpServletRequest request, HttpServletResponse response) throws IOException {
		this.handler.handleLogoutSuccess(request, response);
	}

}
