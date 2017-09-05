package io.github.vpavic.op.oauth2.client;

import java.util.List;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

public interface ClientRepository {

	void save(OIDCClientInformation client);

	OIDCClientInformation findByClientId(ClientID clientID);

	List<OIDCClientInformation> findAll();

	void deleteByClientId(ClientID clientID);

}
