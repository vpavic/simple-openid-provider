package io.github.vpavic.oauth2.client;

import java.util.List;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

public interface ClientRepository {

	void save(OIDCClientInformation client);

	OIDCClientInformation findById(ClientID id);

	List<OIDCClientInformation> findAll();

	void deleteById(ClientID id);

}
