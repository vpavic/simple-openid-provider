package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.oauth2.sdk.ErrorObject;

class NonRedirectingException extends Exception {

	private final int status;

	private final String description;

	NonRedirectingException(int status, String description) {
		this.status = status;
		this.description = description;
	}

	NonRedirectingException(ErrorObject error) {
		this(error.getHTTPStatusCode(), error.getDescription());
	}

	int getStatus() {
		return this.status;
	}

	String getDescription() {
		return this.description;
	}

}
