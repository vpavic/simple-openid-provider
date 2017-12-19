package io.github.vpavic.oauth2.grant.refresh;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/**
 * In-memory implementation of {@link RefreshTokenStore} backed by a {@link ConcurrentMap}.
 *
 * @author Vedran Pavic
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

	private final ConcurrentMap<RefreshToken, RefreshTokenContext> refreshTokens = new ConcurrentHashMap<>();

	@Override
	public void save(RefreshTokenContext context) {
		Objects.requireNonNull(context, "context must not be null");
		this.refreshTokens.put(context.getRefreshToken(), context);
	}

	@Override
	public RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		RefreshTokenContext context = this.refreshTokens.remove(refreshToken);
		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		else if (context.isExpired()) {
			this.refreshTokens.remove(refreshToken);
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		return context;
	}

	@Override
	public RefreshTokenContext findByClientIdAndSubject(ClientID clientId, Subject subject) {
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(subject, "subject must not be null");
		RefreshTokenContext result = null;
		for (Map.Entry<RefreshToken, RefreshTokenContext> entry : this.refreshTokens.entrySet()) {
			RefreshTokenContext context = entry.getValue();
			if (clientId.equals(context.getClientId()) && subject.equals(context.getSubject())) {
				if (context.isExpired()) {
					this.refreshTokens.remove(context.getRefreshToken());
				}
				else {
					result = context;
				}
			}
		}
		return result;
	}

	@Override
	public void revoke(RefreshToken refreshToken) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		this.refreshTokens.remove(refreshToken);
	}

}
