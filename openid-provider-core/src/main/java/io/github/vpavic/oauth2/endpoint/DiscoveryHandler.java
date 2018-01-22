package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Objects;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * Endpoint that publishes server's OpenID Provider Configuration.
 *
 * @author Vedran Pavic
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
public class DiscoveryHandler {

	private final OIDCProviderMetadata providerMetadata;

	private String providerMetadataJson;

	public DiscoveryHandler(OIDCProviderMetadata providerMetadata) {
		Objects.requireNonNull(providerMetadata, "providerMetadata must not be null");
		this.providerMetadata = providerMetadata;
	}

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
