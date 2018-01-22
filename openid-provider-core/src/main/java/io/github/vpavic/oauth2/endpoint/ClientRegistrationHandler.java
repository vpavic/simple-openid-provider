package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientService;

public class ClientRegistrationHandler {

	private final ClientRepository clientRepository;

	private final ClientService clientService;

	private boolean allowOpenRegistration;

	private BearerAccessToken apiAccessToken;

	public ClientRegistrationHandler(ClientRepository clientRepository, ClientService clientService) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(clientService, "clientService must not be null");
		this.clientRepository = clientRepository;
		this.clientService = clientService;
	}

	public void setAllowOpenRegistration(boolean allowOpenRegistration) {
		this.allowOpenRegistration = allowOpenRegistration;
	}

	public void setApiAccessToken(BearerAccessToken apiAccessToken) {
		this.apiAccessToken = apiAccessToken;
	}

	public void getClientRegistrations(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);

		try {
			String authorizationHeader = httpRequest.getAuthorization();

			if (authorizationHeader == null) {
				throw new GeneralException(BearerTokenError.INVALID_TOKEN);
			}

			BearerAccessToken requestAccessToken = BearerAccessToken.parse(authorizationHeader);
			validateAccessToken(requestAccessToken);
			List<OIDCClientInformation> clients = this.clientRepository.findAll();

			response.setContentType("application/json; charset=UTF-8");

			PrintWriter writer = response.getWriter();
			writer.print(toJsonObject(clients).toJSONString());
			writer.close();
		}
		catch (GeneralException e) {
			ClientRegistrationResponse registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
			ServletUtils.applyHTTPResponse(registrationResponse.toHTTPResponse(), response);
		}
	}

	public void handleClientRegistrationRequest(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		ClientRegistrationResponse registrationResponse;

		try {
			OIDCClientRegistrationRequest registrationRequest = OIDCClientRegistrationRequest.parse(httpRequest);

			if (!this.allowOpenRegistration) {
				validateAccessToken(registrationRequest.getAccessToken());
			}

			OIDCClientMetadata clientMetadata = registrationRequest.getOIDCClientMetadata();
			OIDCClientInformation clientInformation = this.clientService.create(clientMetadata, true);

			registrationResponse = new OIDCClientInformationResponse(clientInformation);
		}
		catch (GeneralException e) {
			registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
		}

		ServletUtils.applyHTTPResponse(registrationResponse.toHTTPResponse(), response);
	}

	public void getClientConfiguration(HttpServletRequest request, HttpServletResponse response,
			ClientID id) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		ClientRegistrationResponse registrationResponse;

		try {
			ClientReadRequest clientReadRequest = ClientReadRequest.parse(httpRequest);
			OIDCClientInformation client = resolveAndValidateClient(id, clientReadRequest);
			registrationResponse = new OIDCClientInformationResponse(client);
		}
		catch (GeneralException e) {
			registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
		}

		ServletUtils.applyHTTPResponse(registrationResponse.toHTTPResponse(), response);
	}

	public void updateClientConfiguration(HttpServletRequest request, HttpServletResponse response,
			ClientID id) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		ClientRegistrationResponse registrationResponse;

		try {
			OIDCClientUpdateRequest clientUpdateRequest = OIDCClientUpdateRequest.parse(httpRequest);
			resolveAndValidateClient(id, clientUpdateRequest);

			OIDCClientMetadata clientMetadata = clientUpdateRequest.getOIDCClientMetadata();
			OIDCClientInformation client = this.clientService.update(id, clientMetadata);

			registrationResponse = new OIDCClientInformationResponse(client);
		}
		catch (GeneralException e) {
			registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
		}

		ServletUtils.applyHTTPResponse(registrationResponse.toHTTPResponse(), response);
	}

	public void deleteClientConfiguration(HttpServletRequest request, HttpServletResponse response,
			ClientID id) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);

		try {
			ClientDeleteRequest clientDeleteRequest = ClientDeleteRequest.parse(httpRequest);
			resolveAndValidateClient(id, clientDeleteRequest);

			this.clientRepository.deleteById(id);

			response.setStatus(HttpServletResponse.SC_NO_CONTENT);
		}
		catch (GeneralException e) {
			ClientRegistrationResponse registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
			ServletUtils.applyHTTPResponse(registrationResponse.toHTTPResponse(), response);
		}
	}

	private void validateAccessToken(AccessToken requestAccessToken) throws GeneralException {
		BearerAccessToken apiAccessToken = this.apiAccessToken;

		if (requestAccessToken == null || !requestAccessToken.equals(apiAccessToken)) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}
	}

	private JSONObject toJsonObject(List<OIDCClientInformation> clients) {
		JSONObject object = new JSONObject();
		JSONArray clientList = new JSONArray();
		clients.forEach(client -> clientList.add(client.toJSONObject()));
		object.put("clients", clientList);

		return object;
	}

	private OIDCClientInformation resolveAndValidateClient(ClientID clientId, ProtectedResourceRequest request)
			throws GeneralException {
		OIDCClientInformation client = this.clientRepository.findById(clientId);

		if (client != null) {
			AccessToken requestAccessToken = request.getAccessToken();
			BearerAccessToken registrationAccessToken = client.getRegistrationAccessToken();
			BearerAccessToken apiAccessToken = this.apiAccessToken;

			if (requestAccessToken.equals(registrationAccessToken) || requestAccessToken.equals(apiAccessToken)) {
				return client;
			}
		}

		throw new GeneralException(BearerTokenError.INVALID_TOKEN);
	}

}
