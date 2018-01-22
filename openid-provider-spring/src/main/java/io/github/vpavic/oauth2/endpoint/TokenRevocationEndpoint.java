package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = TokenRevocationEndpoint.PATH_MAPPING)
public class TokenRevocationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/revoke";

	private final TokenHandler handler;

	public TokenRevocationEndpoint(TokenHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@PostMapping
	public void handleRevocationRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		this.handler.handleTokenRevocationRequest(request, response);
	}

}
