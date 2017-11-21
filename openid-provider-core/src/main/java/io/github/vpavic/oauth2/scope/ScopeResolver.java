package io.github.vpavic.oauth2.scope;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

public interface ScopeResolver {

	Scope resolve(Subject subject, Scope requestedScope, OIDCClientMetadata clientMetadata) throws GeneralException;

}
