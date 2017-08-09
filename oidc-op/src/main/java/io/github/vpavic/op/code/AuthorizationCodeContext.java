package io.github.vpavic.op.code;

import java.io.Serializable;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.springframework.security.core.Authentication;

public class AuthorizationCodeContext implements Serializable {

	private final Authentication authentication;

	private final ClientID clientID;

	private final Scope scope;

	private final CodeChallenge codeChallenge;

	private final CodeChallengeMethod codeChallengeMethod;

	private final Nonce nonce;

	public AuthorizationCodeContext(Authentication authentication, ClientID clientID, Scope scope,
			CodeChallenge codeChallenge, CodeChallengeMethod codeChallengeMethod, Nonce nonce) {
		this.authentication = Objects.requireNonNull(authentication);
		this.clientID = Objects.requireNonNull(clientID);
		this.scope = Objects.requireNonNull(scope);
		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		this.nonce = nonce;
	}

	public Authentication getAuthentication() {
		return this.authentication;
	}

	public ClientID getClientID() {
		return this.clientID;
	}

	public Scope getScope() {
		return this.scope;
	}

	public CodeChallenge getCodeChallenge() {
		return this.codeChallenge;
	}

	public CodeChallengeMethod getCodeChallengeMethod() {
		return this.codeChallengeMethod;
	}

	public Nonce getNonce() {
		return this.nonce;
	}

}
