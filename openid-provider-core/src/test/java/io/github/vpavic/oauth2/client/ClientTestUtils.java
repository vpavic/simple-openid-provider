package io.github.vpavic.oauth2.client;

import java.net.URI;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * Collection of utils for client related testing scenarios.
 *
 * @author Vedran Pavic
 */
final class ClientTestUtils {

	private ClientTestUtils() {
	}

	static OIDCClientInformation createClient() {
		ClientID id = new ClientID(UUID.randomUUID().toString());
		Date issueDate = new Date();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		Secret secret = new Secret();
		URI registrationUri = URI.create("http://example.com/register/" + id);
		BearerAccessToken accessToken = new BearerAccessToken();
		return new OIDCClientInformation(id, issueDate, metadata, secret, registrationUri, accessToken);
	}

}
