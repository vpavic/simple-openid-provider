package io.github.vpavic.oauth2.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * In-memory implementation of {@link ClientRepository} backed by a {@link ConcurrentMap}.
 */
public class InMemoryClientRepository implements ClientRepository {

	private final ConcurrentMap<ClientID, OIDCClientInformation> clients = new ConcurrentHashMap<>();

	public InMemoryClientRepository() {
	}

	public InMemoryClientRepository(OIDCClientInformation... clients) {
		Stream.of(clients).forEach(this::save);
	}

	@Override
	public void save(OIDCClientInformation client) {
		Objects.requireNonNull(client, "client must not be null");
		this.clients.put(client.getID(), client);
	}

	@Override
	public OIDCClientInformation findById(ClientID id) {
		Objects.requireNonNull(id, "id must not be null");
		return this.clients.get(id);
	}

	@Override
	public List<OIDCClientInformation> findAll() {
		return Collections.unmodifiableList(new ArrayList<>(this.clients.values()));
	}

	@Override
	public void deleteById(ClientID id) {
		Objects.requireNonNull(id, "id must not be null");
		this.clients.remove(id);
	}

}
