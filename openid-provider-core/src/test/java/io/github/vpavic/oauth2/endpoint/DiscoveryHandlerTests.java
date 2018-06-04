package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.util.Collections;
import java.util.List;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DiscoveryHandler}.
 */
class DiscoveryHandlerTests {

	private DiscoveryHandler discoveryHandler;

	@Test
	void construct_NullProviderMetadata_ShouldThrowException() {
		assertThatThrownBy(() -> new DiscoveryHandler(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("providerMetadata must not be null");
	}

	@Test
	@SuppressWarnings("unchecked")
	void getProviderMetadata_ValidProviderMetadata_ShouldReturnResponse() {
		this.discoveryHandler = new DiscoveryHandler(new OIDCProviderMetadata(new Issuer("http://example.com"),
				Collections.singletonList(SubjectType.PUBLIC), URI.create("http://example.com/jwks.json")));
		HTTPResponse response = this.discoveryHandler.getProviderMetadata();

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
		DocumentContext ctx = JsonPath.parse(response.getContent());
		assertThat(ctx.read("$.issuer", String.class)).isEqualTo("http://example.com");
		assertThat(ctx.read("$.subject_types_supported", List.class)).contains("public");
		assertThat(ctx.read("$.jwks_uri", String.class)).isEqualTo("http://example.com/jwks.json");
	}

	// TODO add more tests

}
