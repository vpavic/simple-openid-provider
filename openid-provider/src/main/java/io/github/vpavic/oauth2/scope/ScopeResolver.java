package io.github.vpavic.oauth2.scope;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

public interface ScopeResolver {

	Scope resolve(Subject subject, OIDCClientInformation client, Scope requestedScope);

}
