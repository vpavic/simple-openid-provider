package io.github.vpavic.oauth2.endsession;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.client.ClientRepository;

@Controller
@RequestMapping(path = EndSessionEndpoint.PATH_MAPPING)
public class EndSessionEndpoint {

	public static final String PATH_MAPPING = "/oauth2/logout";

	private static final String POST_LOGOUT_REDIRECT_URI_PARAMETER = "post_logout_redirect_uri";

	private static final String STATE_PARAMETER = "state";

	private static final String LOGOUT_PROMPT_VIEW_NAME = "oauth2/logout-prompt";

	private static final String LOGOUT_SUCCESS_VIEW_NAME = "oauth2/logout-success";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public EndSessionEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
	}

	@GetMapping
	public String getLogoutPrompt(ServletWebRequest request, Model model) throws ParseException {
		if (this.properties.isLogoutEnabled()) {
			LogoutRequest logoutRequest = resolveLogoutRequest(request);

			if (logoutRequest != null) {
				model.addAttribute("redirectURI", logoutRequest.getPostLogoutRedirectionURI());
				model.addAttribute("state", logoutRequest.getState());
			}
		}

		return LOGOUT_PROMPT_VIEW_NAME;
	}

	@PostMapping
	public String handleLogoutSuccess(WebRequest request, Model model) {
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
				postLogoutRedirectUri = resolveDefaultPostLogoutRedirectUri();
			}
		}
		else {
			postLogoutRedirectUri = resolveDefaultPostLogoutRedirectUri();
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

	private LogoutRequest resolveLogoutRequest(ServletWebRequest request) throws ParseException {
		String query = request.getRequest().getQueryString();

		return (query != null) ? LogoutRequest.parse(query) : null;
	}

	private String resolveDefaultPostLogoutRedirectUri() {
		return UriComponentsBuilder.fromHttpUrl(this.properties.getIssuer().getValue()).path("/login").query("logout")
				.toUriString();
	}

}
