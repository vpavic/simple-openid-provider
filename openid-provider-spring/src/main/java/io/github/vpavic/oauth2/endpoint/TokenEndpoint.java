package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = TokenEndpoint.PATH_MAPPING)
public class TokenEndpoint {

	public static final String PATH_MAPPING = "/oauth2/token";

	private final TokenHandler handler;

	public TokenEndpoint(TokenHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@PostMapping
	public void handleTokenRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse = this.handler.handleTokenRequest(httpRequest);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

}
