package io.github.vpavic.op.config;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
public class SessionConfiguration {

	private final ServerProperties properties;

	public SessionConfiguration(ServerProperties properties) {
		this.properties = properties;
	}

	@Bean
	public CookieSerializer cookieSerializer() {
		ServerProperties.Session.Cookie sessionCookie = this.properties.getSession().getCookie();

		DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
		cookieSerializer.setCookieName(sessionCookie.getName());
		cookieSerializer.setUseHttpOnlyCookie(sessionCookie.getHttpOnly());

		return cookieSerializer;
	}

}
