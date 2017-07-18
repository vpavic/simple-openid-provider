package io.github.vpavic.code;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.springframework.stereotype.Service;

@Service
public class MapAuthorizationCodeService implements AuthorizationCodeService {

	private final ConcurrentMap<String, Tokens> store = new ConcurrentHashMap<>();

	@Override
	public AuthorizationCode create(Tokens tokens) {
		AuthorizationCode code = new AuthorizationCode();
		this.store.put(code.getValue(), tokens);
		return code;
	}

	@Override
	public Tokens consume(AuthorizationCode code) {
		Tokens tokens = this.store.remove(code.getValue());
		if (tokens == null) {
			throw new IllegalArgumentException("Invalid code " + code);
		}
		return tokens;
	}

}
