package io.github.vpavic.op.endpoint;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping(path = LoginEndpoint.PATH_MAPPING)
public class LoginEndpoint {

	public static final String PATH_MAPPING = "/login";

	private static final String LOGIN_VIEW_NAME = "login";

	private static final String ERROR_PARAMETER_NAME = "error";

	private static final String DEFAULT_ERROR_MESSAGE = "Unable to authenticate";

	@GetMapping
	public ModelAndView login(ServletWebRequest request) {
		ModelMap model = new ModelMap();

		String continueUri = (String) request.getAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE,
				RequestAttributes.SCOPE_SESSION);

		if (continueUri != null) {
			model.addAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE, continueUri);
		}

		if (request.getParameter(ERROR_PARAMETER_NAME) != null) {
			AuthenticationException error = (AuthenticationException) request
					.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, RequestAttributes.SCOPE_SESSION);
			model.addAttribute(ERROR_PARAMETER_NAME, error != null ? error.getMessage() : DEFAULT_ERROR_MESSAGE);
		}

		return new ModelAndView(LOGIN_VIEW_NAME, model);
	}

}
