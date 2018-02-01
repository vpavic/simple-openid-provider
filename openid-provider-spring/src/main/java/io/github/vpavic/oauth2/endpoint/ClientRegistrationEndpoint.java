package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = ClientRegistrationEndpoint.PATH_MAPPING)
public class ClientRegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final ClientRegistrationHandler handler;

	public ClientRegistrationEndpoint(ClientRegistrationHandler handler) {
		Objects.requireNonNull(handler, "handler must not be null");
		this.handler = handler;
	}

	@GetMapping
	public void getClientRegistrations(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse = this.handler.getClientRegistrations(httpRequest);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

	@PostMapping
	public void handleClientRegistrationRequest(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse = this.handler.handleClientRegistrationRequest(httpRequest);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

	@GetMapping(path = "/{id:.*}")
	public void getClientConfiguration(HttpServletRequest request, HttpServletResponse response,
			@PathVariable ClientID id) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse = this.handler.getClientConfiguration(httpRequest, id);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

	@PutMapping(path = "/{id:.*}")
	public void updateClientConfiguration(HttpServletRequest request, HttpServletResponse response,
			@PathVariable ClientID id) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse = this.handler.updateClientConfiguration(httpRequest, id);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

	@DeleteMapping(path = "/{id:.*}")
	public void deleteClientConfiguration(HttpServletRequest request, HttpServletResponse response,
			@PathVariable ClientID id) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse = this.handler.deleteClientConfiguration(httpRequest, id);
		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

}
