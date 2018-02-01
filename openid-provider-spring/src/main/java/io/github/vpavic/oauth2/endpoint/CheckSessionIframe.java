package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = CheckSessionIframe.PATH_MAPPING)
public class CheckSessionIframe {

	public static final String PATH_MAPPING = "/oauth2/check-session";

	private final CheckSessionHandler handler;

	public CheckSessionIframe(CheckSessionHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void checkSession(HttpServletResponse response) throws IOException {
		HTTPResponse httpResponse = this.handler.checkSession();
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

}
