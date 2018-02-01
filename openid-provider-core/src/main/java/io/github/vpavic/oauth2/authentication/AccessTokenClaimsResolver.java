package io.github.vpavic.oauth2.authentication;

import java.util.Map;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.token.AccessToken;

/**
 * A strategy for resolving claims attached to {@link AccessToken}.
 */
public interface AccessTokenClaimsResolver {

	Map<String, Object> resolveClaims(AccessToken accessToken) throws GeneralException;

}
