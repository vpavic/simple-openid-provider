package io.github.vpavic.oauth2.claim;

import java.util.Set;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public interface ClaimSource {

	UserInfo load(Subject subject, Set<String> claims);

}
