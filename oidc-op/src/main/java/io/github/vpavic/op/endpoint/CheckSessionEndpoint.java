package io.github.vpavic.op.endpoint;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Check session iframe endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-session-1_0.html">OpenID Connect Session Management 1.0</a>
 */
@Controller
@RequestMapping(path = CheckSessionEndpoint.PATH_MAPPING)
public class CheckSessionEndpoint {

	public static final String PATH_MAPPING = "/oauth2/check-session";

	// @formatter:off
	private static final String CHECK_SESSION_PAGE_HTML_TEMPLATE = "<!DOCTYPE html>"
			+ "<html>"
			+ "<head>"
			+ "<title>check_session_iframe</title>"
			+ "<script src=\":baseURI/webjars/cryptojs/components/core-min.js\"></script>"
			+ "<script src=\":baseURI/webjars/cryptojs/components/enc-base64-min.js\"></script>"
			+ "<script src=\":baseURI/webjars/cryptojs/components/sha256-min.js\"></script>"
			+ "<script>"
			+ "window.addEventListener(\"message\", receiveMessage, false);"
			+ "function receiveMessage(e) {"
			+ "if (document.referrer.lastIndexOf(e.origin, 0) !== 0) {"
			+ "return;"
			+ "}"
			+ "if (typeof e.data !== \"string\") {"
			+ "postStatus(e, \"error\");"
			+ "return;"
			+ "}"
			+ "var messageTokens = e.data.split(\" \");"
			+ "var clientId = messageTokens[0];"
			+ "var sessionState = messageTokens[1];"
			+ "if (typeof sessionState === \"undefined\") {"
			+ "postStatus(e, \"error\");"
			+ "return;"
			+ "}"
			+ "var salt = sessionState.split(\".\")[1];"
			+ "if (typeof salt === \"undefined\") {"
			+ "postStatus(e, \"error\");"
			+ "return;"
			+ "}"
			+ "var calculatedSessionState = calculateSessionState(clientId, e.origin, salt);"
			+ "var status = (sessionState === calculatedSessionState) ? \"unchanged\" : \"changed\";"
			+ "postStatus(e, status);"
			+ "}"
			+ "function postStatus(e, stat) {"
			+ "te.source.postMessage(stat, e.origin);"
			+ "}"
			+ "function calculateSessionState(clientId, origin, salt) {"
			+ "var opBrowserState = getOpBrowserState();"
			+ "return CryptoJS.SHA256(clientId + \" \" + origin + \" \" + opBrowserState + \" \" + salt) + \".\" + salt;"
			+ "}"
			+ "function getOpBrowserState() {"
			+ "var cookie = getCookie(\"sid\");"
			+ "var sid = CryptoJS.enc.Base64.parse(cookie);"
			+ "return CryptoJS.enc.Utf8.stringify(sid);"
			+ "}"
			+ "function getCookie(name) {"
			+ "var nameWithSeparator = name + \"=\";"
			+ "var decodedCookie = decodeURIComponent(document.cookie);"
			+ "var cookies = decodedCookie.split(\";\");"
			+ "for (var i = 0; i < cookies.length; i++) {"
			+ "var cookie = cookies[i];"
			+ "while (cookie.charAt(0) === \" \") {"
			+ "cookie = cookie.substring(1);"
			+ "}"
			+ "if (cookie.indexOf(nameWithSeparator) === 0) {"
			+ "return cookie.substring(nameWithSeparator.length);"
			+ "}"
			+ "}"
			+ "return \"\";"
			+ "}"
			+ "</script>"
			+ "</head>"
			+ "</html>";
	// @formatter:on

	@GetMapping
	public void checkSession(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String logoutPageHtml = generateCheckSessionPageHtml(request);
		response.setContentType("text/html;charset=UTF-8");
		response.getWriter().write(logoutPageHtml);
	}

	private String generateCheckSessionPageHtml(HttpServletRequest request) {
		String baseURI = UriComponentsBuilder.newInstance().scheme(request.getScheme()).host(request.getServerName())
				.port(request.getServerPort()).path(request.getContextPath()).toUriString();

		return CHECK_SESSION_PAGE_HTML_TEMPLATE.replace(":baseURI", baseURI);
	}

}
