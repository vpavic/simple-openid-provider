package io.github.vpavic.op.endpoint;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping(path = LoginEndpoint.PATH_MAPPING)
public class LoginEndpoint {

	public static final String PATH_MAPPING = "/login";

	private static final String LOGIN_VIEW_NAME = "login";

	private static final String ERROR_PARAMETER_NAME = "error";

	private static final String DEFAULT_ERROR_MESSAGE = "Unable to authenticate";

	@GetMapping
	public ModelAndView login() {
		return new ModelAndView(LOGIN_VIEW_NAME);
	}

	@GetMapping(params = ERROR_PARAMETER_NAME)
	public ModelAndView loginError(
			@SessionAttribute(name = WebAttributes.AUTHENTICATION_EXCEPTION, required = false) AuthenticationException e) {
		ModelMap model = new ModelMap();
		model.addAttribute(ERROR_PARAMETER_NAME, e != null ? e.getMessage() : DEFAULT_ERROR_MESSAGE);

		return new ModelAndView(LOGIN_VIEW_NAME, model);
	}

}
