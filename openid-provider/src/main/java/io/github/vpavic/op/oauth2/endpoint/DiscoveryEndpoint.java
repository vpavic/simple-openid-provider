package io.github.vpavic.op.oauth2.endpoint;

import java.util.Objects;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint that publishes server's OpenID Provider Configuration.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
@RestController
@RequestMapping(path = DiscoveryEndpoint.PATH_MAPPING)
public class DiscoveryEndpoint {

	public static final String PATH_MAPPING = "/.well-known/openid-configuration";

	private final String providerMetadata;

	public DiscoveryEndpoint(OIDCProviderMetadata providerMetadata) {
		Objects.requireNonNull(providerMetadata, "providerMetadata must not be null");

		this.providerMetadata = providerMetadata.toJSONObject().toJSONString();
	}

	@GetMapping
	public ResponseEntity<String> getProviderMetadata() {
		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(this.providerMetadata);
		// @formatter:on
	}

}
