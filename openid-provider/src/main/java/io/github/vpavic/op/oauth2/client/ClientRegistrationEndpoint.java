package io.github.vpavic.op.oauth2.client;

import java.net.URI;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.mvc.method.annotation.MvcUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Controller
@RequestMapping(path = ClientRegistrationEndpoint.PATH_MAPPING)
public class ClientRegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final String clientIdSuffix;

	public ClientRegistrationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
		this.clientIdSuffix = UriComponentsBuilder.fromHttpUrl(properties.getIssuer().getValue()).build().getHost();
	}

	@PostMapping
	public ResponseEntity<String> handleRegistrationRequest(ServletWebRequest request) throws Exception {
		OIDCClientRegistrationRequest registrationRequest = resolveRegistrationRequest(request);

		validateAccessToken(registrationRequest);

		String id = UUID.randomUUID().toString() + "." + this.clientIdSuffix;
		OIDCClientMetadata metadata = registrationRequest.getOIDCClientMetadata();
		metadata.applyDefaults();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = new Secret();
		}

		URI registrationUri = MvcUriComponentsBuilder.fromController(ClientConfigurationEndpoint.class).build(id);
		OIDCClientInformation clientInformation = new OIDCClientInformation(new ClientID(id), new Date(), metadata,
				secret, registrationUri, new BearerAccessToken());

		this.clientRepository.save(clientInformation);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(clientInformation.toJSONObject().toJSONString());
		// @formatter:on
	}

	@ExceptionHandler(GeneralException.class)
	public ResponseEntity<String> handleGeneralException(GeneralException e) {
		ErrorObject error = e.getErrorObject();

		// @formatter:off
		return ResponseEntity.status(error.getHTTPStatusCode())
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(error.toJSONObject().toJSONString());
		// @formatter:on
	}

	private OIDCClientRegistrationRequest resolveRegistrationRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());

		return OIDCClientRegistrationRequest.parse(httpRequest);
	}

	private void validateAccessToken(OIDCClientRegistrationRequest request) throws GeneralException {
		if (!this.properties.getRegistration().isOpenRegistrationEnabled()) {
			AccessToken requestAccessToken = request.getAccessToken();
			BearerAccessToken apiAccessToken = this.properties.getRegistration().getApiAccessToken();

			if (requestAccessToken == null || !requestAccessToken.equals(apiAccessToken)) {
				throw new GeneralException(BearerTokenError.INVALID_TOKEN);
			}
		}
	}

}
