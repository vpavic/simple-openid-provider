package io.github.vpavic.oauth2.jwk;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Objects;

import javax.annotation.PostConstruct;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

/**
 * A simple {@link JwkSetLoader} implementation that loads JWK set from the given {@link Resource}.
 *
 * @author Vedran Pavic
 */
public class ResourceJwkSetLoader implements JwkSetLoader {

	private final Resource jwkSetResource;

	private JWKSet jwkSet;

	public ResourceJwkSetLoader(Resource jwkSetResource) {
		Objects.requireNonNull(jwkSetResource, "jwkSetResource must not be null");

		this.jwkSetResource = jwkSetResource;
	}

	@PostConstruct
	public void init() {
		try {
			byte[] bytes = FileCopyUtils.copyToByteArray(this.jwkSetResource.getInputStream());
			this.jwkSet = JWKSet.parse(new String(bytes, StandardCharsets.UTF_8));
		}
		catch (IOException | ParseException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public JWKSet load() {
		return this.jwkSet;
	}

}
