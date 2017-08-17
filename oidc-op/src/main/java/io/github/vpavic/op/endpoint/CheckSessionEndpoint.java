package io.github.vpavic.op.endpoint;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

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

	@GetMapping
	public String checkSession() {
		return "oauth2/check-session";
	}

}
