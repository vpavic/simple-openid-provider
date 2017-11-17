package io.github.vpavic.oauth2.grant.refresh;

import java.time.Instant;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;

/**
 * Collection of utils for refresh token related testing scenarios.
 *
 * @author Vedran Pavic
 */
final class RefreshTokenTestUtils {

	private RefreshTokenTestUtils() {
	}

	static RefreshTokenContext createRefreshTokenContext(Instant expiry) {
		return new RefreshTokenContext(new Subject("test"), new ClientID(), new Scope(), expiry);
	}

}
