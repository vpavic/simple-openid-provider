package io.github.vpavic.oauth2.endpoint;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
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

	public HTTPResponse getProviderMetadata() {
		HTTPResponse httpResponse;

		try {
			if (this.providerMetadataJson == null) {
				this.providerMetadataJson = serializeProviderMetadata();
			}

			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
			httpResponse.setContentType("application/json; charset=UTF-8");
			httpResponse.setContent(this.providerMetadataJson);
		}
		catch (Exception e) {
			httpResponse = new HTTPResponse(HTTPResponse.SC_SERVER_ERROR);
		}

		return httpResponse;
	}

	private String serializeProviderMetadata() {
		return this.providerMetadata.toJSONObject().toJSONString();
	}

}
