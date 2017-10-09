package io.github.vpavic.op.config;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
public class SessionConfiguration {

	private final ServerProperties.Session.Cookie properties;

	public SessionConfiguration(ServerProperties properties) {
		this.properties = properties.getSession().getCookie();
	}

	@Bean
	public CookieSerializer cookieSerializer() {
		DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
		cookieSerializer.setCookieName(this.properties.getName());
		cookieSerializer.setUseHttpOnlyCookie(this.properties.getHttpOnly());

		return cookieSerializer;
	}

}
