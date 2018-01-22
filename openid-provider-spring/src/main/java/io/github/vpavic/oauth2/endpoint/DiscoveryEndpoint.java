package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = DiscoveryEndpoint.PATH_MAPPING)
public class DiscoveryEndpoint {

	public static final String PATH_MAPPING = "/.well-known/openid-configuration";

	private final DiscoveryHandler handler;

	public DiscoveryEndpoint(DiscoveryHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void getProviderMetadata(HttpServletResponse response) throws IOException {
		this.handler.getProviderMetadata(response);
	}

}
