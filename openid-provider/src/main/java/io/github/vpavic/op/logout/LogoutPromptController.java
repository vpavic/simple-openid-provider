package io.github.vpavic.op.logout;

import java.net.URI;

import com.nimbusds.oauth2.sdk.id.State;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/logout")
public class LogoutPromptController {

	@GetMapping
	public String logoutPrompt(@RequestAttribute(name = "idToken", required = false) String idToken,
			@RequestAttribute(name = "redirectUri", required = false) URI redirectUri,
			@RequestAttribute(name = "state", required = false) State state, Model model) {
		model.addAttribute("idToken", idToken);
		model.addAttribute("redirectUri", redirectUri);
		model.addAttribute("state", state);
		return "logout";
	}

}
