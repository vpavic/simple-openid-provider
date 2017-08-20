package io.github.vpavic.op.endpoint;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = LogoutEndpoint.PATH_MAPPING)
public class LogoutEndpoint {

	public static final String PATH_MAPPING = "/logout";

	@GetMapping
	public String logoutPrompt(HTTPRequest httpRequest, Model model) throws ParseException {
		if (httpRequest.getQuery() != null) {
			LogoutRequest request = LogoutRequest.parse(httpRequest);

			model.addAttribute("redirectURI", request.getPostLogoutRedirectionURI());
			model.addAttribute("state", request.getState());
		}

		return "logout";
	}

}
