package io.github.vpavic.op.oauth2.sdk.auth.verifier;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import io.github.vpavic.op.client.ClientRepository;

public class ClientRepositoryClientCredentialsSelector implements ClientCredentialsSelector<ClientRepository> {

	@Override
	public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod,
			Context<ClientRepository> context) throws InvalidClientException {
		OIDCClientInformation client = resolveClient(context.get(), claimedClientID);

		if (!authMethod.equals(client.getOIDCMetadata().getTokenEndpointAuthMethod())) {
			return Collections.emptyList();
		}

		return Collections.singletonList(client.getSecret());
	}

	@Override
	public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod,
			JWSHeader jwsHeader, boolean forceRefresh, Context<ClientRepository> context)
			throws InvalidClientException {
		resolveClient(context.get(), claimedClientID);

		return Collections.emptyList();
	}

	private OIDCClientInformation resolveClient(ClientRepository clientRepository, ClientID clientID)
			throws InvalidClientException {
		OIDCClientInformation client = clientRepository.findByClientId(clientID);

		if (client == null) {
			throw InvalidClientException.BAD_ID;
		}

		return client;
	}

}
