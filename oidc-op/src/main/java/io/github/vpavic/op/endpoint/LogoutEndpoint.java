package io.github.vpavic.op.endpoint;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Controller
@RequestMapping(path = LogoutEndpoint.PATH_MAPPING)
public class LogoutEndpoint {

	public static final String PATH_MAPPING = "/logout";

	private static final String LOGOUT_VIEW_NAME = "logout";

	private final OpenIdProviderProperties properties;

	public LogoutEndpoint(OpenIdProviderProperties properties) {
		this.properties = properties;
	}

	@GetMapping
	public ModelAndView logoutPrompt(HttpServletRequest request) throws ParseException {
		ModelMap model = new ModelMap();

		if (this.properties.isSessionManagementOrFrontChannelLogoutEnabled()) {
			LogoutRequest logoutRequest = resolveLogoutRequest(request);

			if (logoutRequest != null) {
				model.addAttribute("redirectURI", logoutRequest.getPostLogoutRedirectionURI());
				model.addAttribute("state", logoutRequest.getState());
			}
		}

		return new ModelAndView(LOGOUT_VIEW_NAME, model);
	}

	private LogoutRequest resolveLogoutRequest(HttpServletRequest request) throws ParseException {
		String query = request.getQueryString();

		return query != null ? LogoutRequest.parse(query) : null;
	}

}
