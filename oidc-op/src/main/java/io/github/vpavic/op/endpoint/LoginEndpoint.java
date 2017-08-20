package io.github.vpavic.op.endpoint;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttribute;

@Controller
@RequestMapping(path = LoginEndpoint.PATH_MAPPING)
public class LoginEndpoint {

	public static final String PATH_MAPPING = "/login";

	@GetMapping
	public String login() {
		return "login";
	}

	@GetMapping(params = "error")
	public String loginError(Model model,
			@SessionAttribute(name = WebAttributes.AUTHENTICATION_EXCEPTION, required = false) AuthenticationException e) {
		model.addAttribute("error", e != null ? e.getMessage() : "Unable to authenticate");
		return "login";
	}

}
