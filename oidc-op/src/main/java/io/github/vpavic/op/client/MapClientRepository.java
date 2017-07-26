package io.github.vpavic.op.client;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.stereotype.Service;

@Service
public class MapClientRepository implements ClientRepository {

	private final ConcurrentMap<String, OIDCClientInformation> store = new ConcurrentHashMap<>();

	@Override
	public void save(OIDCClientInformation client) {
		this.store.put(client.getID().getValue(), client);
	}

	@Override
	public OIDCClientInformation findByClientId(ClientID clientID) {
		return this.store.get(clientID.getValue());
	}

}
