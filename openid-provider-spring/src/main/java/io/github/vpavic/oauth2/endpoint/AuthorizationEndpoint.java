package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = AuthorizationEndpoint.PATH_MAPPING)
public class AuthorizationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/authorize";

	public static final String AUTH_REQUEST_URI_ATTRIBUTE = "continue";

	private final AuthorizationHandler handler;

	public AuthorizationEndpoint(AuthorizationHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void authorize(HttpServletRequest request, HttpServletResponse response) throws IOException {
		AuthorizationResponse authResponse;

		try {
			Principal principal = request.getUserPrincipal();
			if (principal != null) {
				HttpSession session = request.getSession();
				authResponse = this.handler.authorize(request.getQueryString(), new Subject(principal.getName()),
						Instant.ofEpochMilli(session.getCreationTime()), new ACR("1"),
						Collections.singletonList(AMR.PWD), new SessionID(session.getId()));
			}
			else {
				authResponse = this.handler.authorize(request.getQueryString(), null, null, null, null, null);
			}
		}
		catch (LoginRequiredException e) {
			loginRedirect(request, response, e.getAuthenticationRequest());
			return;
		}
		catch (NonRedirectingException e) {
			response.sendError(e.getStatus(), e.getDescription());
			return;
		}

		if (ResponseMode.FORM_POST.equals(authResponse.getResponseMode())) {
			response.setContentType("text/html");

			PrintWriter writer = response.getWriter();
			writer.print(prepareFormPostPage(authResponse));
			writer.close();
		}
		else {
			ServletUtils.applyHTTPResponse(authResponse.toHTTPResponse(), response);
		}
	}

	private void loginRedirect(HttpServletRequest request, HttpServletResponse response,
			AuthenticationRequest authRequest) throws IOException {
		Prompt prompt = authRequest.getPrompt();
		String authRequestQuery;

		if (prompt != null && prompt.contains(Prompt.Type.LOGIN)) {
			// @formatter:off
			Map<String, String> authRequestParams = authRequest.toParameters().entrySet().stream()
					.filter(entry -> !entry.getKey().equals("prompt"))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			// @formatter:on

			authRequestQuery = URLUtils.serializeParameters(authRequestParams);
		}
		else {
			authRequestQuery = authRequest.toQueryString();
		}

		String authRequestUri = PATH_MAPPING + "?" + authRequestQuery;
		request.getSession().setAttribute(AUTH_REQUEST_URI_ATTRIBUTE, authRequestUri);

		response.sendRedirect("/login");
	}

	private String prepareFormPostPage(AuthorizationResponse authResponse) {
		State state = authResponse.getState();
		AuthorizationCode code = null;
		AccessToken accessToken = null;
		JWT idToken = null;
		State sessionState = null;

		if (authResponse instanceof AuthenticationSuccessResponse) {
			AuthenticationSuccessResponse authSuccessResponse = (AuthenticationSuccessResponse) authResponse;
			code = authSuccessResponse.getAuthorizationCode();
			accessToken = authSuccessResponse.getAccessToken();
			idToken = authSuccessResponse.getIDToken();
			sessionState = authSuccessResponse.getSessionState();
		}

		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>");
		sb.append("<html>");
		sb.append("<head>");
		sb.append("<meta charset=\"utf-8\">");
		sb.append("<title>Form Post</title>");
		sb.append("</head>");
		sb.append("<body onload=\"document.forms[0].submit()\">");
		sb.append("<form method=\"post\" action=\"").append(authResponse.getRedirectionURI()).append("\">");
		if (code != null) {
			sb.append("<input type=\"hidden\" name=\"code\" value=\"").append(code).append("\"/>");
		}
		if (accessToken != null) {
			sb.append("<input type=\"hidden\" name=\"access_token\" value=\"").append(accessToken).append("\"/>");
		}
		if (idToken != null) {
			sb.append("<input type=\"hidden\" name=\"id_token\" value=\"").append(idToken).append("\"/>");
		}
		if (state != null) {
			sb.append("<input type=\"hidden\" name=\"state\" value=\"").append(state).append("\"/>");
		}
		if (sessionState != null) {
			sb.append("<input type=\"hidden\" name=\"session_state\" value=\"").append(sessionState).append("\"/>");
		}
		sb.append("</form>");
		sb.append("</body>");
		sb.append("</html>");

		return sb.toString();
	}

}
