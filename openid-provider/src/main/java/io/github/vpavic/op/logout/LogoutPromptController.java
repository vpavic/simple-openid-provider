package io.github.vpavic.op.logout;

import com.nimbusds.openid.connect.sdk.LogoutRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/logout")
public class LogoutPromptController {

	@GetMapping
	public String logoutPrompt(@RequestAttribute(name = "logoutRequest") LogoutRequest logoutRequest, Model model) {
		model.addAttribute("logoutRequest", logoutRequest);
		return "logout";
	}

}
