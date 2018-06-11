package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.apache.http.client.utils.URIBuilder;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

public class EndSessionHandler {

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private final ClientRepository clientRepository;

	private URI defaultPostLogoutRedirectUri;

	private boolean frontChannelLogoutEnabled;

	public EndSessionHandler(Issuer issuer, JwkSetLoader jwkSetLoader, ClientRepository clientRepository) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
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
			URI postLogoutRedirectUri = resolvePostLogoutRedirectUri(logoutRequest);

			if (postLogoutRedirectUri == null) {
				postLogoutRedirectUri = resolveDefaultPostLogoutRedirectUri();
			}

			List<URI> frontChannelLogoutUris = resolveFrontChannelLogoutUris(sessionId);

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

	private URI resolvePostLogoutRedirectUri(LogoutRequest logoutRequest)
			throws java.text.ParseException, URISyntaxException {
		JWT idToken = logoutRequest.getIDTokenHint();
		URI postLogoutRedirectUri = logoutRequest.getPostLogoutRedirectionURI();
		URI resolvedPostLogoutRedirectUri = null;

		if (idToken != null && postLogoutRedirectUri != null) {
			Algorithm algorithm = idToken.getHeader().getAlgorithm();
			JWKSet jwkSet = this.jwkSetLoader.load();
			JWSVerificationKeySelector jwsVerificationKeySelector = new JWSVerificationKeySelector<>(
					(JWSAlgorithm) algorithm, new ImmutableJWKSet<>(jwkSet));

			for (String audience : idToken.getJWTClaimsSet().getAudience()) {
				ClientID clientId = new ClientID(audience);
				IDTokenValidator idTokenValidator = new IDTokenValidator(this.issuer, clientId,
						jwsVerificationKeySelector, null);
				try {
					idTokenValidator.validate(idToken, null);
				}
				catch (Exception e) {
					continue;
				}
				OIDCClientInformation client = this.clientRepository.findById(clientId);
				if (client == null) {
					continue;
				}
				Set<URI> postLogoutRedirectionUris = client.getOIDCMetadata().getPostLogoutRedirectionURIs();
				if (postLogoutRedirectionUris == null || !postLogoutRedirectionUris.contains(postLogoutRedirectUri)) {
					continue;
				}
				resolvedPostLogoutRedirectUri = postLogoutRedirectUri;
				State state = logoutRequest.getState();
				if (state != null) {
					// @formatter:off
						resolvedPostLogoutRedirectUri = new URIBuilder(resolvedPostLogoutRedirectUri)
								.addParameter("state", state.getValue())
								.build();
						// @formatter:on
				}
			}
		}

		return resolvedPostLogoutRedirectUri;
	}

	private URI resolveDefaultPostLogoutRedirectUri() {
		if (this.defaultPostLogoutRedirectUri == null) {
			try {
				// @formatter:off
				this.defaultPostLogoutRedirectUri = new URIBuilder(URI.create(this.issuer.getValue()))
						.setPath("/login")
						.setCustomQuery("logout")
						.build();
				// @formatter:on
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		return this.defaultPostLogoutRedirectUri;
	}

	private List<URI> resolveFrontChannelLogoutUris(SessionID sessionId) {
		List<URI> frontChannelLogoutUris = Collections.emptyList();

		if (this.frontChannelLogoutEnabled) {
			List<OIDCClientInformation> clients = this.clientRepository.findAll();

			// @formatter:off
			frontChannelLogoutUris = clients.stream()
					.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
					.filter(Objects::nonNull)
					.map(uri -> buildFrontChannelLogoutUri(uri, sessionId.getValue()))
					.collect(Collectors.toList());
			// @formatter:on
		}

		return frontChannelLogoutUris;
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
