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
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

public class DefaultClientService implements ClientService {

	private final Issuer issuer;

	private final ClientRepository clientRepository;

	private boolean refreshSecretOnUpdate;

	private boolean refreshAccessTokenOnUpdate;

	public DefaultClientService(Issuer issuer, ClientRepository clientRepository) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.issuer = issuer;
		this.clientRepository = clientRepository;
	}

	public void setRefreshSecretOnUpdate(boolean refreshSecretOnUpdate) {
		this.refreshSecretOnUpdate = refreshSecretOnUpdate;
	}

	public void setRefreshAccessTokenOnUpdate(boolean refreshAccessTokenOnUpdate) {
		this.refreshAccessTokenOnUpdate = refreshAccessTokenOnUpdate;
	}

	@Override
	@Transactional
	public OIDCClientInformation create(OIDCClientMetadata metadata) {
		metadata.applyDefaults();
		ClientID clientId = new ClientID(UUID.randomUUID().toString());
		Instant issueDate = Instant.now();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = new Secret();
		}

		URI registrationUri = UriComponentsBuilder.fromHttpUrl(this.issuer.getValue()).path("/oauth2/register/{id}")
				.build(clientId.getValue());
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientInformation client = new OIDCClientInformation(clientId, Date.from(issueDate), metadata, secret,
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
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = this.refreshSecretOnUpdate ? new Secret() : client.getSecret();
		}

		BearerAccessToken accessToken = this.refreshAccessTokenOnUpdate ? new BearerAccessToken()
				: client.getRegistrationAccessToken();

		client = new OIDCClientInformation(id, client.getIDIssueDate(), metadata, secret, client.getRegistrationURI(),
				accessToken);
		this.clientRepository.save(client);

		return client;
	}

}
