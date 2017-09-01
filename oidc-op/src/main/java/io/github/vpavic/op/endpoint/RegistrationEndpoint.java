package io.github.vpavic.op.endpoint;

import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import net.minidev.json.JSONObject;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.config.OpenIdProviderProperties;

@RestController
@RequestMapping(path = RegistrationEndpoint.PATH_MAPPING)
public class RegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public RegistrationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		this.properties = properties;
		this.clientRepository = Objects.requireNonNull(clientRepository);
	}

	@PostMapping
	public JSONObject handleRegistrationRequest(ServletWebRequest request) throws Exception {
		OIDCClientRegistrationRequest registrationRequest = resolveRegistrationRequest(request);

		// @formatter:off
		String host = UriComponentsBuilder.fromHttpUrl(this.properties.getIssuer())
				.build()
				.getHost();
		// @formatter:on

		OIDCClientMetadata clientMetadata = registrationRequest.getOIDCClientMetadata();
		ClientID clientID = new ClientID(UUID.randomUUID().toString() + "." + host);
		OIDCClientInformation clientInformation = new OIDCClientInformation(clientID, new Date(), clientMetadata,
				new Secret());

		this.clientRepository.save(clientInformation);

		return clientInformation.toJSONObject();
	}

	private OIDCClientRegistrationRequest resolveRegistrationRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());

		return OIDCClientRegistrationRequest.parse(httpRequest);
	}

}
