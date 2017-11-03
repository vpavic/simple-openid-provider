package io.github.vpavic.oauth2.logout;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.oauth2.client.ClientRepository;

@RequestMapping(path = EndSessionEndpoint.PATH_MAPPING)
public class EndSessionEndpoint {

	public static final String PATH_MAPPING = "/oauth2/logout";

	private static final String POST_LOGOUT_REDIRECT_URI_PARAMETER = "post_logout_redirect_uri";

	private static final String STATE_PARAMETER = "state";

	private static final String LOGOUT_PROMPT_FORWARD_URI = "forward:/logout";

	private final Issuer issuer;

	private final ClientRepository clientRepository;

	private boolean frontChannelLogoutEnabled;

	public EndSessionEndpoint(Issuer issuer, ClientRepository clientRepository) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.issuer = issuer;
		this.clientRepository = clientRepository;
	}

	public void setFrontChannelLogoutEnabled(boolean frontChannelLogoutEnabled) {
		this.frontChannelLogoutEnabled = frontChannelLogoutEnabled;
	}

	@GetMapping
	public ModelAndView getLogoutPrompt(HTTPRequest httpRequest) throws ParseException {
		Map<String, Object> model = new HashMap<>();

		if (httpRequest.getQuery() != null) {
			LogoutRequest logoutRequest = LogoutRequest.parse(httpRequest.getQuery());
			model.put("redirectURI", logoutRequest.getPostLogoutRedirectionURI());
			model.put("state", logoutRequest.getState());
		}

		return new ModelAndView(LOGOUT_PROMPT_FORWARD_URI, model);
	}

	@PostMapping
	public ResponseEntity<String> handleLogoutSuccess(WebRequest request) {
		String postLogoutRedirectUri = request.getParameter(POST_LOGOUT_REDIRECT_URI_PARAMETER);

		List<OIDCClientInformation> clients = this.clientRepository.findAll();

		if (StringUtils.hasText(postLogoutRedirectUri)) {
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

		List<String> frontChannelLogoutUris = new ArrayList<>();

		if (this.frontChannelLogoutEnabled) {
			String sessionId = request.getSessionId();

			// @formatter:off
			frontChannelLogoutUris = clients.stream()
					.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
					.filter(Objects::nonNull)
					.map(uri -> buildFrontChannelLogoutUri(uri, sessionId))
					.collect(Collectors.toList());
			// @formatter:on
		}

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.TEXT_HTML)
				.body(prepareLogoutSuccessPage(postLogoutRedirectUri, frontChannelLogoutUris));
		// @formatter:on
	}

	private String resolveDefaultPostLogoutRedirectUri() {
		// @formatter:off
		return UriComponentsBuilder.fromHttpUrl(this.issuer.getValue())
				.path("/login")
				.query("logout")
				.toUriString();
		// @formatter:on
	}

	private String buildFrontChannelLogoutUri(URI uri, String sessionId) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(uri)
				.queryParam("iss", this.issuer)
				.queryParam("sid", sessionId)
				.toUriString();
		// @formatter:on
	}

	private String prepareLogoutSuccessPage(String postLogoutRedirectUri, List<String> frontChannelLogoutUris) {
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>");
		sb.append("<html>");
		sb.append("<head>");
		sb.append("<meta charset=\"utf-8\">");
		sb.append("<title>Logout Success</title>");
		sb.append("<script>");
		sb.append("window.onload = function() {");
		sb.append("window.location.href = '").append(postLogoutRedirectUri).append("';");
		sb.append("}");
		sb.append("</script>");
		sb.append("</head>");
		sb.append("<body>");
		for (String frontChannelLogoutUri : frontChannelLogoutUris) {
			sb.append("<iframe style=\"display:block; visibility:hidden\" src=\"").append(frontChannelLogoutUri)
					.append("></iframe>");
		}
		sb.append("</body>");
		sb.append("</html>");

		return sb.toString();
	}

}
