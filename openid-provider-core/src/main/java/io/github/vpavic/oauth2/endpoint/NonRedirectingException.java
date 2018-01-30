package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class NonRedirectingException extends Exception {

	private final int status;

	private final String description;

	NonRedirectingException(ErrorObject error) {
		this.status = error.getHTTPStatusCode();
		this.description = error.getDescription();
	}

	public int getStatus() {
		return this.status;
	}

	public String getDescription() {
		return this.description;
	}

}
