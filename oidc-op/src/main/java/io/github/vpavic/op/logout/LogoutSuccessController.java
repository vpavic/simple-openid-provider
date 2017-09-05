package io.github.vpavic.op.logout;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.oauth2.client.ClientRepository;

@Controller
@RequestMapping(path = LogoutSuccessController.PATH_MAPPING)
public class LogoutSuccessController {

	public static final String PATH_MAPPING = "/logout/success";

	private static final String POST_LOGOUT_REDIRECT_URI_PARAMETER = "post_logout_redirect_uri";

	private static final String STATE_PARAMETER = "state";

	private static final String DEFAULT_POST_LOGOUT_REDIRECT_URI = "/login?logout";

	private static final String LOGOUT_SUCCESS_VIEW_NAME = "logout/success";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public LogoutSuccessController(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "properties must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
	}

	@PostMapping
	public String logoutSuccess(WebRequest request, Model model) {
		String postLogoutRedirectUri = request.getParameter(POST_LOGOUT_REDIRECT_URI_PARAMETER);

		List<OIDCClientInformation> clients = this.clientRepository.findAll();

		if (this.properties.isLogoutEnabled() && StringUtils.hasText(postLogoutRedirectUri)) {
			// @formatter:off
			Set<String> postLogoutRedirectUris = clients.stream()
					.flatMap(client -> Optional.ofNullable(client.getOIDCMetadata().getPostLogoutRedirectionURIs())
							.orElse(Collections.emptySet()).stream())
					.filter(Objects::nonNull)
					.map(URI::toString)
					.collect(Collectors.toSet());
			// @formatter:on

			if (postLogoutRedirectUris.contains(postLogoutRedirectUri)) {
				String state = request.getParameter(STATE_PARAMETER);

				if (state != null) {
					// @formatter:off
					postLogoutRedirectUri = UriComponentsBuilder.fromHttpUrl(postLogoutRedirectUri)
							.queryParam("state", state)
							.toUriString();
					// @formatter:on
				}
			}
			else {
				postLogoutRedirectUri = DEFAULT_POST_LOGOUT_REDIRECT_URI;
			}
		}
		else {
			postLogoutRedirectUri = DEFAULT_POST_LOGOUT_REDIRECT_URI;
		}

		model.addAttribute("postLogoutRedirectUri", postLogoutRedirectUri);

		if (this.properties.getFrontChannelLogout().isEnabled()) {
			List<String> frontChannelLogoutUris = new ArrayList<>();

			// @formatter:off
			List<String> registeredFrontChannelLogoutUris = clients.stream()
					.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
					.filter(Objects::nonNull)
					.map(URI::toString)
					.collect(Collectors.toList());
			// @formatter:on

			String sessionId = request.getSessionId();

			for (String frontChannelLogoutUri : registeredFrontChannelLogoutUris) {
				// @formatter:off
				frontChannelLogoutUri = UriComponentsBuilder.fromHttpUrl(frontChannelLogoutUri)
						.queryParam("iss", this.properties.getIssuer())
						.queryParam("sid", sessionId)
						.toUriString();
				// @formatter:on

				frontChannelLogoutUris.add(frontChannelLogoutUri);
			}

			model.addAttribute("frontChannelLogoutUris", frontChannelLogoutUris);
		}

		return LOGOUT_SUCCESS_VIEW_NAME;
	}

}
