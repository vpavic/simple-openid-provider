package io.github.vpavic.oauth2.grant.code;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;

/**
 * In-memory implementation of {@link AuthorizationCodeService} backed by a {@link ConcurrentMap}.
 *
 * @author Vedran Pavic
 */
public class InMemoryAuthorizationCodeService implements AuthorizationCodeService {

	private final ConcurrentMap<AuthorizationCode, AuthorizationCodeContext> codes = new ConcurrentHashMap<>();

	@Override
	public AuthorizationCode create(AuthorizationCodeContext context) {
		Objects.requireNonNull(context, "context must not be null");
		AuthorizationCode code = new AuthorizationCode();
		this.codes.put(code, context);
		return code;
	}

	@Override
	public AuthorizationCodeContext consume(AuthorizationCode code) throws GeneralException {
		Objects.requireNonNull(code, "code must not be null");
		AuthorizationCodeContext context = this.codes.remove(code);
		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		return context;
	}

}
