package io.github.vpavic.op.config;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.op.client.ClientRepository;

@Component
public class OIDCLogoutSuccessHandler implements LogoutSuccessHandler {

	private static final String REDIRECT_URI_PARAMETER = "post_logout_redirect_uri";

	private static final String STATE_PARAMETER = "state";

	// @formatter:off
	private static final String LOGOUT_PAGE_HTML_TEMPLATE = "<!DOCTYPE html>"
			+ "<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\">"
			+ "<head>"
			+ "</head>"
			+ "<body>"
			+ ":iframes"
			+ "<script>"
			+ "window.onload = function() {"
			+ "window.location.href = ':redirectURI';"
			+ "}"
			+ "</script>"
			+ "</body>";
	// @formatter:on

	private static final String LOGOUT_PAGE_IFRAME_TEMPLATE = "<iframe style=\"display:block; visibility:hidden\" "
			+ "src=\"${clientLogoutUrl}\"></iframe>";

	private final String defaultRedirectURI;

	private final ClientRepository clientRepository;

	public OIDCLogoutSuccessHandler(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		this.defaultRedirectURI = properties.getIssuer();
		this.clientRepository = Objects.requireNonNull(clientRepository);
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		String logoutPageHtml = generateLogoutPageHtml(request);
		response.setContentType("text/html;charset=UTF-8");
		response.getWriter().write(logoutPageHtml);
	}

	private String generateLogoutPageHtml(HttpServletRequest request) {
		String redirectURI = request.getParameter(REDIRECT_URI_PARAMETER);

		List<OIDCClientInformation> clients = this.clientRepository.findAll();

		if (StringUtils.hasText(redirectURI)) {
			// @formatter:off
			Set<String> redirectURIs = clients.stream()
					.flatMap(client -> Optional.ofNullable(client.getOIDCMetadata().getPostLogoutRedirectionURIs())
							.orElse(Collections.emptySet()).stream())
					.filter(Objects::nonNull)
					.map(URI::toString)
					.collect(Collectors.toSet());
			// @formatter:on

			if (redirectURIs.contains(redirectURI)) {
				String state = request.getParameter(STATE_PARAMETER);

				if (state != null) {
					// @formatter:off
					redirectURI = UriComponentsBuilder.fromHttpUrl(redirectURI)
							.queryParam("state", state)
							.build()
							.toUriString();
					// @formatter:on
				}
			}
			else {
				redirectURI = this.defaultRedirectURI;
			}
		}
		else {
			redirectURI = this.defaultRedirectURI;
		}

		StringBuilder iframes = new StringBuilder();

		// @formatter:off
		Set<String> logoutURIs = clients.stream()
				.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
				.filter(Objects::nonNull)
				.map(URI::toString)
				.collect(Collectors.toSet());
		// @formatter:on

		for (String clientLogoutURI : logoutURIs) {
			iframes.append(LOGOUT_PAGE_IFRAME_TEMPLATE.replace(":clientLogoutUrl", clientLogoutURI));
		}

		return LOGOUT_PAGE_HTML_TEMPLATE.replace(":iframes", iframes.toString()).replace(":redirectURI", redirectURI);
	}

}
