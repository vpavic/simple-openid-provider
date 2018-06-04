package io.github.vpavic.oauth2.endpoint;

import java.util.List;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.jwk.JwkSetLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link JwkSetHandler}.
 */
class JwkSetHandlerTests {

	private JwkSetLoader jwkSetLoader = mock(JwkSetLoader.class);

	private JwkSetHandler jwkSetHandler;

	@BeforeEach
	void setUp() {
		reset(this.jwkSetLoader);
	}

	@Test
	void construct_NullJwkSetLoader_ShouldThrowException() {
		assertThatThrownBy(() -> new JwkSetHandler(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("jwkSetLoader must not be null");
	}

	@Test
	void getJwkSet_WithNoKeysLoaded_ShouldReturnResponse() {
		given(this.jwkSetLoader.load()).willReturn(new JWKSet());

		this.jwkSetHandler = new JwkSetHandler(this.jwkSetLoader);
		HTTPResponse response = this.jwkSetHandler.getJwkSet();

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("application/jwk-set+json; charset=UTF-8");
		DocumentContext ctx = JsonPath.parse(response.getContent());
		assertThat(ctx.read("$.keys", List.class)).isEmpty();
	}

	// TODO add more tests

}
