package io.github.vpavic.oauth2.grant.refresh;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/**
 * In-memory implementation of {@link RefreshTokenStore} backed by a {@link ConcurrentMap}.
 *
 * @author Vedran Pavic
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

	private final ConcurrentMap<RefreshToken, RefreshTokenContext> refreshTokens = new ConcurrentHashMap<>();

	@Override
	public void save(RefreshToken refreshToken, RefreshTokenContext context) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		Objects.requireNonNull(context, "context must not be null");
		this.refreshTokens.put(refreshToken, context);
	}

	@Override
	public RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		RefreshTokenContext context = this.refreshTokens.remove(refreshToken);
		if (context == null || context.isExpired()) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		return context;
	}

	@Override
	public void revoke(RefreshToken refreshToken) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		this.refreshTokens.remove(refreshToken);
	}

}
