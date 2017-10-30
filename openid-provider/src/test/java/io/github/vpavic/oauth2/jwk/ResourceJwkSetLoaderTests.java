package io.github.vpavic.oauth2.jwk;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ResourceJwkSetLoader}.
 */
public class ResourceJwkSetLoaderTests {

	private ResourceJwkSetLoader jwkSetLoader;

	@Before
	public void setUp() {
		ClassPathResource jwkSetResource = new ClassPathResource("jwks.json");
		this.jwkSetLoader = new ResourceJwkSetLoader(jwkSetResource);
		this.jwkSetLoader.init();
	}

	@Test
	public void load() {
		JWKSet jwkSet = this.jwkSetLoader.load();

		assertThat(jwkSet).isNotNull();
		assertThat(jwkSet.getKeys()).hasSize(4);
	}

}
