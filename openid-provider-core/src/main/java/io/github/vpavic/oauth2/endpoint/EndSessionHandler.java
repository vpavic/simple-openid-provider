package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.apache.http.client.utils.URIBuilder;

import io.github.vpavic.oauth2.client.ClientRepository;

public class EndSessionHandler {

	private final Issuer issuer;

	private final ClientRepository clientRepository;

	private boolean frontChannelLogoutEnabled;

	public EndSessionHandler(Issuer issuer, ClientRepository clientRepository) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		this.issuer = issuer;
		this.clientRepository = clientRepository;
	}

	public void setFrontChannelLogoutEnabled(boolean frontChannelLogoutEnabled) {
		this.frontChannelLogoutEnabled = frontChannelLogoutEnabled;
	}

	public HTTPResponse handleLogoutSuccess(HTTPRequest httpRequest, SessionID sessionId) {
		HTTPResponse httpResponse;

		try {
			Map<String, String> params = httpRequest.getQueryParameters();
			LogoutRequest logoutRequest = LogoutRequest.parse(params);

			List<OIDCClientInformation> clients = this.clientRepository.findAll();
			URI postLogoutRedirectUri = logoutRequest.getPostLogoutRedirectionURI();

			if (postLogoutRedirectUri != null) {
				// @formatter:off
				Set<String> postLogoutRedirectUris = clients.stream()
						.flatMap(client -> Optional.ofNullable(client.getOIDCMetadata().getPostLogoutRedirectionURIs())
								.orElse(Collections.emptySet()).stream())
						.filter(Objects::nonNull)
						.map(URI::toString)
						.collect(Collectors.toSet());
				// @formatter:on

				if (postLogoutRedirectUris.contains(postLogoutRedirectUri.toString())) {
					State state = logoutRequest.getState();

					if (state != null) {
						// @formatter:off
						postLogoutRedirectUri = new URIBuilder(postLogoutRedirectUri)
								.addParameter("state", state.getValue())
								.build();
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

			List<URI> frontChannelLogoutUris = Collections.emptyList();

			if (this.frontChannelLogoutEnabled) {
				// @formatter:off
				frontChannelLogoutUris = clients.stream()
						.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
						.filter(Objects::nonNull)
						.map(uri -> buildFrontChannelLogoutUri(uri, sessionId.getValue()))
						.collect(Collectors.toList());
				// @formatter:on
			}

			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
			httpResponse.setContentType("text/html");
			httpResponse.setContent(prepareLogoutSuccessPage(postLogoutRedirectUri, frontChannelLogoutUris));
		}
		catch (ParseException e) {
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		}
		catch (Exception e) {
			httpResponse = new HTTPResponse(HTTPResponse.SC_SERVER_ERROR);
		}

		return httpResponse;
	}

	private URI resolveDefaultPostLogoutRedirectUri() {
		try {
			// @formatter:off
			return new URIBuilder(URI.create(this.issuer.getValue()))
					.setPath("/login")
					.setCustomQuery("logout")
					.build();
			// @formatter:on
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private URI buildFrontChannelLogoutUri(URI uri, String sessionId) {
		try {
			// @formatter:off
			return new URIBuilder(uri)
					.addParameter("iss", this.issuer.getValue())
					.addParameter("sid", sessionId)
					.build();
			// @formatter:on
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private String prepareLogoutSuccessPage(URI postLogoutRedirectUri, List<URI> frontChannelLogoutUris) {
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
		for (URI frontChannelLogoutUri : frontChannelLogoutUris) {
			sb.append("<iframe style=\"display:block; visibility:hidden\" src=\"").append(frontChannelLogoutUri)
					.append("\"></iframe>");
		}
		sb.append("</body>");
		sb.append("</html>");

		return sb.toString();
	}

}
