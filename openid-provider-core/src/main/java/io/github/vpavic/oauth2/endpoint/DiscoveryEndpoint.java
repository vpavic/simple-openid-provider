package io.github.vpavic.oauth2.endpoint;

import java.util.Objects;

import javax.annotation.PostConstruct;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Endpoint that publishes server's OpenID Provider Configuration.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
@RequestMapping(path = DiscoveryEndpoint.PATH_MAPPING)
public class DiscoveryEndpoint {

	public static final String PATH_MAPPING = "/.well-known/openid-configuration";

	private final OIDCProviderMetadata providerMetadata;

	private String providerMetadataJson;

	public DiscoveryEndpoint(OIDCProviderMetadata providerMetadata) {
		Objects.requireNonNull(providerMetadata, "providerMetadata must not be null");
		this.providerMetadata = providerMetadata;
	}

	@PostConstruct
	public void init() {
		this.providerMetadataJson = this.providerMetadata.toJSONObject().toJSONString();
	}

	@GetMapping
	public ResponseEntity<String> getProviderMetadata() {
		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(this.providerMetadataJson);
		// @formatter:on
	}

}
