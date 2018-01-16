package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
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

	@GetMapping
	public void getProviderMetadata(HttpServletResponse response) throws IOException {
		if (this.providerMetadataJson == null) {
			this.providerMetadataJson = serializeProviderMetadata();
		}

		response.setContentType("application/json; charset=UTF-8");

		PrintWriter writer = response.getWriter();
		writer.print(this.providerMetadataJson);
		writer.close();
	}

	private String serializeProviderMetadata() {
		return this.providerMetadata.toJSONObject().toJSONString();
	}

}
