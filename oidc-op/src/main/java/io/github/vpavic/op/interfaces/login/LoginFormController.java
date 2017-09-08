package io.github.vpavic.op.interfaces.login;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;

import io.github.vpavic.op.oauth2.endpoint.AuthorizationEndpoint;

@Controller
@RequestMapping(path = LoginFormController.PATH_MAPPING)
public class LoginFormController {

	public static final String PATH_MAPPING = "/login";

	private static final String ERROR_PARAMETER_NAME = "error";

	private static final String LOGIN_FORM_VIEW_NAME = "login";

	private static final String DEFAULT_ERROR_MESSAGE = "Unable to authenticate";

	@GetMapping
	public String getLoginForm(WebRequest request, Model model) {
		String continueUri = (String) request.getAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE,
				RequestAttributes.SCOPE_SESSION);

		if (continueUri != null) {
			model.addAttribute(AuthorizationEndpoint.AUTH_REQUEST_URI_ATTRIBUTE, continueUri);
		}

		return LOGIN_FORM_VIEW_NAME;
	}

	@GetMapping(params = ERROR_PARAMETER_NAME)
	public String getLoginErrorForm(WebRequest request, Model model) {
		AuthenticationException error = (AuthenticationException) request
				.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, RequestAttributes.SCOPE_SESSION);
		model.addAttribute(ERROR_PARAMETER_NAME, error != null ? error.getMessage() : DEFAULT_ERROR_MESSAGE);

		return getLoginForm(request, model);
	}

}
