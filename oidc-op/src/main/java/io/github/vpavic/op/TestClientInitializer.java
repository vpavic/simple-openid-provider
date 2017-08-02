package io.github.vpavic.op;

import java.net.URI;
import java.util.Date;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import io.github.vpavic.op.client.ClientRepository;

@Component
public class TestClientInitializer implements CommandLineRunner {

	private final ClientRepository clientRepository;

	public TestClientInitializer(ClientRepository clientRepository) {
		this.clientRepository = Objects.requireNonNull(clientRepository);
	}

	@Override
	public void run(String... args) throws Exception {
		ClientID clientID = new ClientID("test-client");
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://localhost:7979/oauth2/authorize/code/test-client"));
		clientMetadata.setScope(new Scope(OIDCScopeValue.OPENID));
		Secret secret = new Secret("test-secret");

		this.clientRepository.save(new OIDCClientInformation(clientID, new Date(), clientMetadata, secret));
	}

}
