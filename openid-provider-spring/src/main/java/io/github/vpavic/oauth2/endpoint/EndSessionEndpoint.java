package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.server.ResponseStatusException;

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
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		LogoutRequest logoutRequest;
		try {
			logoutRequest = LogoutRequest.parse(httpRequest.getQuery());
		}
		catch (ParseException e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
		request.setAttribute("logoutRequest", logoutRequest);
		request.getRequestDispatcher("/logout").forward(request, response);
	}

	@PostMapping
	public void handleLogoutSuccess(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		SessionID sessionId = new SessionID(request.getSession().getId());
		HTTPResponse httpResponse = this.handler.handleLogoutSuccess(httpRequest, sessionId);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

}
