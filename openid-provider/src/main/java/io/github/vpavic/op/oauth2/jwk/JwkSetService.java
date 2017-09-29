package io.github.vpavic.op.oauth2.jwk;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public interface JwkSetService extends JWKSource<SecurityContext> {

	void rotate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException;

}
