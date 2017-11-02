package io.github.vpavic.oauth2.claim;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public interface UserClaimsLoader {

	UserInfo load(Subject subject, Scope scope);

}
