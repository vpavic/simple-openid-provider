package io.github.vpavic.oauth2.authentication;

import org.springframework.security.core.Authentication;

/**
 * A strategy for resolving {@link Authentication} from Bearer token.
 *
 * @author Vedran Pavic
 */
public interface BearerTokenAuthenticationResolver {

	Authentication resolveAuthentication(String bearerToken) throws Exception;

}
