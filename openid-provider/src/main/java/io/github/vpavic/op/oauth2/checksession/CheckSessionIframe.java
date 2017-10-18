package io.github.vpavic.op.oauth2.checksession;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
@ConditionalOnProperty(prefix = "op.session-management", name = "enabled", havingValue = "true")
@RequestMapping(path = CheckSessionIframe.PATH_MAPPING)
public class CheckSessionIframe {

	public static final String PATH_MAPPING = "/oauth2/check-session";

	private static final String CHECK_SESSION_VIEW_NAME = "oauth2/check-session";

	@GetMapping
	public String checkSession() {
		return CHECK_SESSION_VIEW_NAME;
	}

}
