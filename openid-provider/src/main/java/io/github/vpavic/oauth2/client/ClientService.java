package io.github.vpavic.oauth2.client;

import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

public interface ClientService {

	OIDCClientInformation create(OIDCClientMetadata metadata, boolean dynamicRegistration);

	OIDCClientInformation update(ClientID id, OIDCClientMetadata metadata) throws InvalidClientException;

}
