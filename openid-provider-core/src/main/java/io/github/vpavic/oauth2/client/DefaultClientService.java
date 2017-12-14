package io.github.vpavic.oauth2.client;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.transaction.annotation.Transactional;

public class DefaultClientService implements ClientService {

	private final ClientRepository clientRepository;

	private final String registrationUriTemplate;

	private boolean refreshSecretOnUpdate;

	private boolean refreshAccessTokenOnUpdate;

	public DefaultClientService(ClientRepository clientRepository, String registrationUriTemplate) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(registrationUriTemplate, "registrationUriTemplate must not be null");
		this.clientRepository = clientRepository;
		this.registrationUriTemplate = registrationUriTemplate;
	}

	public void setRefreshSecretOnUpdate(boolean refreshSecretOnUpdate) {
		this.refreshSecretOnUpdate = refreshSecretOnUpdate;
	}

	public void setRefreshAccessTokenOnUpdate(boolean refreshAccessTokenOnUpdate) {
		this.refreshAccessTokenOnUpdate = refreshAccessTokenOnUpdate;
	}

	@Override
	@Transactional
	public OIDCClientInformation create(OIDCClientMetadata metadata, boolean dynamicRegistration) {
		metadata.applyDefaults();
		ClientID id = new ClientID(UUID.randomUUID().toString());
		Instant issueDate = Instant.now();
		Secret secret = isTokenEndpointAuthEnabled(metadata) ? new Secret() : null;
		URI registrationUri = dynamicRegistration
				? URI.create(this.registrationUriTemplate.replace("{id}", id.getValue()))
				: null;
		BearerAccessToken accessToken = dynamicRegistration ? new BearerAccessToken() : null;

		OIDCClientInformation client = new OIDCClientInformation(id, Date.from(issueDate), metadata, secret,
				registrationUri, accessToken);
		this.clientRepository.save(client);

		return client;
	}

	@Override
	@Transactional
	public OIDCClientInformation update(ClientID id, OIDCClientMetadata metadata) throws InvalidClientException {
		OIDCClientInformation client = this.clientRepository.findById(id);

		if (client == null) {
			throw InvalidClientException.BAD_ID;
		}

		metadata.applyDefaults();
		Secret secret = isTokenEndpointAuthEnabled(metadata)
				? (this.refreshSecretOnUpdate || client.getSecret() == null ? new Secret() : client.getSecret())
				: null;
		BearerAccessToken accessToken = (client.getRegistrationURI() != null)
				? (this.refreshAccessTokenOnUpdate ? new BearerAccessToken() : client.getRegistrationAccessToken())
				: null;

		client = new OIDCClientInformation(id, client.getIDIssueDate(), metadata, secret, client.getRegistrationURI(),
				accessToken);
		this.clientRepository.save(client);

		return client;
	}

	private boolean isTokenEndpointAuthEnabled(OIDCClientMetadata metadata) {
		return !ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod());
	}

}
