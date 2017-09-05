package io.github.vpavic.op.logout;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Controller
@RequestMapping(path = LogoutPromptController.PATH_MAPPING)
public class LogoutPromptController {

	public static final String PATH_MAPPING = "/logout";

	private static final String LOGOUT_PROMPT_VIEW_NAME = "logout/prompt";

	private final OpenIdProviderProperties properties;

	public LogoutPromptController(OpenIdProviderProperties properties) {
		Objects.requireNonNull(properties, "properties must not be null");

		this.properties = properties;
	}

	@GetMapping
	public String logoutConfirmation(ServletWebRequest request, Model model) throws ParseException {
		if (this.properties.isLogoutEnabled()) {
			LogoutRequest logoutRequest = resolveLogoutRequest(request);

			if (logoutRequest != null) {
				model.addAttribute("redirectURI", logoutRequest.getPostLogoutRedirectionURI());
				model.addAttribute("state", logoutRequest.getState());
			}
		}

		return LOGOUT_PROMPT_VIEW_NAME;
	}

	private LogoutRequest resolveLogoutRequest(ServletWebRequest request) throws ParseException {
		String query = request.getRequest().getQueryString();

		return (query != null) ? LogoutRequest.parse(query) : null;
	}

}
