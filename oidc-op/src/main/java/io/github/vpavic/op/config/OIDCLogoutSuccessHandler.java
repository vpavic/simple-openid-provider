package io.github.vpavic.op.config;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Objects;
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

import io.github.vpavic.op.client.ClientRepository;

@Component
public class OIDCLogoutSuccessHandler implements LogoutSuccessHandler {

	private static final String DEFAULT_TARGET_URL = SecurityConfiguration.LOGIN_URL + "?logout";

	private static final String TARGET_URL_PARAMETER = "post_logout_redirect_uri";

	// @formatter:off
	private static final String LOGOUT_PAGE_HTML_TEMPLATE = "<!DOCTYPE html>"
			+ "<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\">"
			+ "<head>"
			+ "</head>"
			+ "<body>"
			+ ":iframes"
			+ "<script>"
			+ "window.onload = function() {"
			+ "window.location.href = ':targetUrl';"
			+ "}"
			+ "</script>"
			+ "</body>";
	// @formatter:on

	private static final String LOGOUT_PAGE_IFRAME_TEMPLATE = "<iframe style=\"display:block; visibility:hidden\" "
			+ "src=\"${clientLogoutUrl}\"></iframe>";

	private final ClientRepository clientRepository;

	public OIDCLogoutSuccessHandler(ClientRepository clientRepository) {
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
		String targetUrlParameter = request.getParameter(TARGET_URL_PARAMETER);
		String targetUrl = StringUtils.hasText(targetUrlParameter) ? targetUrlParameter : DEFAULT_TARGET_URL;

		List<OIDCClientInformation> clients = this.clientRepository.findAll();

		StringBuilder iframes = new StringBuilder();

		// @formatter:off
		Set<URI> clientLogoutURIs = clients.stream()
				.map(client -> client.getOIDCMetadata().getFrontChannelLogoutURI())
				.filter(Objects::nonNull)
				.collect(Collectors.toSet());
		// @formatter:on

		for (URI clientLogoutURI : clientLogoutURIs) {
			iframes.append(LOGOUT_PAGE_IFRAME_TEMPLATE.replace(":clientLogoutUrl", clientLogoutURI.toString()));
		}

		return LOGOUT_PAGE_HTML_TEMPLATE.replace(":iframes", iframes.toString()).replace(":targetUrl", targetUrl);
	}

}
