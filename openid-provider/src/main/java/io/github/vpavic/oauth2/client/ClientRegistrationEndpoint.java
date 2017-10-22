package io.github.vpavic.oauth2.client;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
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

import io.github.vpavic.oauth2.OpenIdProviderProperties;

@Controller
@RequestMapping(path = ClientRegistrationEndpoint.PATH_MAPPING)
public class ClientRegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final OpenIdProviderProperties properties;

	private final ClientService clientService;

	public ClientRegistrationEndpoint(OpenIdProviderProperties properties, ClientService clientService) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientService, "clientService must not be null");

		this.properties = properties;
		this.clientService = clientService;
	}

	@PostMapping
	public ResponseEntity<String> handleRegistrationRequest(ServletWebRequest request) throws Exception {
		OIDCClientRegistrationRequest registrationRequest = resolveRegistrationRequest(request);

		validateAccessToken(registrationRequest);

		OIDCClientMetadata clientMetadata = registrationRequest.getOIDCClientMetadata();
		OIDCClientInformation clientInformation = this.clientService.create(clientMetadata);

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
