package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.oauth2.sdk.ErrorObject;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AuthorizationRequestException extends ResponseStatusException {

	private final ErrorObject error;

	AuthorizationRequestException(ErrorObject error) {
		super(HttpStatus.valueOf(error.getHTTPStatusCode()), error.getDescription());
		this.error = error;
	}

	ErrorObject getError() {
		return this.error;
	}

}
