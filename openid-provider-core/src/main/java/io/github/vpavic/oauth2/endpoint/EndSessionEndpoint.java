package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.oauth2.client.ClientRepository;

@RequestMapping(path = EndSessionEndpoint.PATH_MAPPING)
public class EndSessionEndpoint {

	public static final String PATH_MAPPING = "/oauth2/logout";

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
	public void getLogoutPrompt(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		if (request.getQueryString() != null) {
			HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);

			try {
				LogoutRequest logoutRequest = LogoutRequest.parse(httpRequest.getQuery());
				request.setAttribute("redirectUri", logoutRequest.getPostLogoutRedirectionURI());
				request.setAttribute("state", logoutRequest.getState());
			}
			catch (ParseException ignored) {
			}
		}

		request.getRequestDispatcher("/logout").forward(request, response);
	}

	@PostMapping
	public void handleLogoutSuccess(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");

		List<OIDCClientInformation> clients = this.clientRepository.findAll();

		if (StringUtils.isNotBlank(postLogoutRedirectUri)) {
			// @formatter:off
			Set<String> postLogoutRedirectUris = clients.stream()
					.flatMap(client -> Optional.ofNullable(client.getOIDCMetadata().getPostLogoutRedirectionURIs())
							.orElse(Collections.emptySet()).stream())
					.filter(Objects::nonNull)
					.map(URI::toString)
					.collect(Collectors.toSet());
			// @formatter:on

			if (postLogoutRedirectUris.contains(postLogoutRedirectUri)) {
				String state = request.getParameter("state");

				if (state != null) {
					// @formatter:off
					postLogoutRedirectUri = new URIBuilder(URI.create(postLogoutRedirectUri))
							.addParameter("state", state)
							.toString();
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
			String sessionId = request.getSession().getId();

			// @formatter:off
			frontChannelLogoutUris = clients.stream()
					.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
					.filter(Objects::nonNull)
					.map(uri -> buildFrontChannelLogoutUri(uri, sessionId))
					.collect(Collectors.toList());
			// @formatter:on
		}

		response.setContentType("text/html");

		PrintWriter writer = response.getWriter();
		writer.print(prepareLogoutSuccessPage(postLogoutRedirectUri, frontChannelLogoutUris));
		writer.close();
	}

	private String resolveDefaultPostLogoutRedirectUri() {

		// @formatter:off
		return new URIBuilder(URI.create(this.issuer.getValue()))
				.setPath("/login")
				.setCustomQuery("logout")
				.toString();
		// @formatter:on
	}

	private String buildFrontChannelLogoutUri(URI uri, String sessionId) {
		// @formatter:off
		return new URIBuilder(uri)
				.addParameter("iss", this.issuer.getValue())
				.addParameter("sid", sessionId)
				.toString();
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
					.append("\"></iframe>");
		}
		sb.append("</body>");
		sb.append("</html>");

		return sb.toString();
	}

}
