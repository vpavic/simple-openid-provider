package io.github.vpavic.op.endpoint;

import java.util.Objects;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONObject;
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
@RequestMapping(path = "/.well-known/openid-configuration")
public class DiscoveryEndpoint {

	private final OIDCProviderMetadata providerMetadata;

	public DiscoveryEndpoint(OIDCProviderMetadata providerMetadata) {
		this.providerMetadata = Objects.requireNonNull(providerMetadata);
	}

	@GetMapping
	public JSONObject providerMetadata() {
		return this.providerMetadata.toJSONObject();
	}

}
