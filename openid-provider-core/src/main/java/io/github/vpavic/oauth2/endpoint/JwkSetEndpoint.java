package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.oauth2.jwk.JwkSetLoader;

/**
 * Endpoint that publishes server's public RSA keys as a JSON Web Key (JWK) set.
 *
 * @author Vedran Pavic
 */
@RequestMapping(path = JwkSetEndpoint.PATH_MAPPING)
public class JwkSetEndpoint {

	public static final String PATH_MAPPING = "/oauth2/keys";

	private final JwkSetLoader jwkSetLoader;

	public JwkSetEndpoint(JwkSetLoader jwkSetLoader) {
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		this.jwkSetLoader = jwkSetLoader;
	}

	@GetMapping
	public void getJwkSet(HttpServletResponse response) throws IOException {
		JWKSet jwkSet = this.jwkSetLoader.load();

		response.setContentType(JWKSet.MIME_TYPE);

		PrintWriter writer = response.getWriter();
		writer.print(jwkSet.toJSONObject().toJSONString());
		writer.close();
	}

}
