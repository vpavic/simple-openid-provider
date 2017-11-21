package io.github.vpavic.oauth2.grant.password;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.id.Subject;

public interface PasswordAuthenticationHandler {

	Subject authenticate(ResourceOwnerPasswordCredentialsGrant grant) throws GeneralException;

}
