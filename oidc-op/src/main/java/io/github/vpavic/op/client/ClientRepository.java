package io.github.vpavic.op.client;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

public interface ClientRepository {

	void save(OIDCClientInformation client);

	OIDCClientInformation findByClientId(ClientID clientID);

	void deleteByClientId(ClientID clientID);

}
