package io.github.vpavic.oauth2.grant.code;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;

/**
 * Collection of utils for authorization code related testing scenarios.
 */
final class AuthorizationCodeTestUtils {

	private AuthorizationCodeTestUtils() {
	}

	static AuthorizationCodeContext createAuthorizationCodeContext() {
		return new AuthorizationCodeContext(new Subject("test"), new ClientID("test"), URI.create("http://example.com"),
				new Scope(), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD), new SessionID("test"),
				null, null, null);
	}

}
