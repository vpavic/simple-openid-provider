package io.github.vpavic.oauth2.token;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.apache.commons.collections4.SetUtils;

import io.github.vpavic.oauth2.grant.refresh.RefreshTokenContext;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;

public class DefaultRefreshTokenService implements RefreshTokenService {

	private final RefreshTokenStore refreshTokenStore;

	private Duration refreshTokenLifetime = Duration.ZERO;

	public DefaultRefreshTokenService(RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public RefreshToken createRefreshToken(RefreshTokenRequest refreshTokenRequest) {
		Instant now = Instant.now();
		ClientID clientId = refreshTokenRequest.getClientId();
		Subject subject = refreshTokenRequest.getSubject();
		Scope scope = refreshTokenRequest.getScope();

		RefreshTokenContext context = this.refreshTokenStore.findByClientIdAndSubject(clientId, subject);

		if (context == null || !SetUtils.isEqualSet(context.getScope(), scope)) {
			if (context != null) {
				this.refreshTokenStore.revoke(context.getRefreshToken());
			}
			Instant expiry = (!this.refreshTokenLifetime.isZero() && !this.refreshTokenLifetime.isNegative())
					? now.plus(this.refreshTokenLifetime)
					: null;
			context = new RefreshTokenContext(new RefreshToken(), clientId, subject, scope, expiry);
			this.refreshTokenStore.save(context);
		}

		return context.getRefreshToken();
	}

	public void setRefreshTokenLifetime(Duration refreshTokenLifetime) {
		this.refreshTokenLifetime = refreshTokenLifetime;
	}

}
