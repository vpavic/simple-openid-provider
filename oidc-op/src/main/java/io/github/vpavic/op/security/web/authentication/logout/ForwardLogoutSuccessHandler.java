package io.github.vpavic.op.security.web.authentication.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

public class ForwardLogoutSuccessHandler implements LogoutSuccessHandler {

	private final String targetUrl;

	public ForwardLogoutSuccessHandler(String targetUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(targetUrl), "'" + targetUrl + "' is not a valid target URL");
		this.targetUrl = targetUrl;
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		request.getRequestDispatcher(this.targetUrl).forward(request, response);
	}

}
