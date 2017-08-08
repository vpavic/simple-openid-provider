package io.github.vpavic.op.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.springframework.security.core.userdetails.UserDetails;

public interface TokenService {

	AccessToken createAccessToken(UserDetails principal, ClientID clientID, Scope scope);

	RefreshToken createRefreshToken();

	JWT createIdToken(UserDetails principal, ClientID clientID, Scope scope, Nonce nonce);

}
