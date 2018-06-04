package io.github.vpavic.oauth2.grant.refresh;

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.RefreshTokenService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link RefreshTokenGrantHandler}.
 */
class RefreshTokenGrantHandlerTests {

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private AccessTokenService accessTokenService = mock(AccessTokenService.class);

	private RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);

	private RefreshTokenStore refreshTokenStore = mock(RefreshTokenStore.class);

	private RefreshTokenGrantHandler grantHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
		reset(this.accessTokenService);
		reset(this.refreshTokenService);
		reset(this.refreshTokenStore);
	}

	@Test
	void refreshToken_basicAuth_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");
		BearerAccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.refreshTokenStore.load(eq(refreshToken))).willReturn(new RefreshTokenContext(
				refreshToken, clientId, new Subject("test-user"), new Scope("test-scope"), null));
		this.grantHandler = new RefreshTokenGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.refreshTokenStore);

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/tokens"), clientAuth,
				new RefreshTokenGrant(refreshToken));
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(Tokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
	}

	@Test
	void refreshToken_postAuth_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");
		BearerAccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.refreshTokenStore.load(eq(refreshToken))).willReturn(new RefreshTokenContext(refreshToken,
				clientId, new Subject("test-user"), new Scope("test-scope"), null));
		this.grantHandler = new RefreshTokenGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.refreshTokenStore);

		ClientSecretPost clientAuth = new ClientSecretPost(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/tokens"), clientAuth,
				new RefreshTokenGrant(refreshToken));
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(Tokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
	}

	// TODO add more tests

	private static OIDCClientInformation client(ClientAuthenticationMethod clientAuthenticationMethod) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com/cb"));
		clientMetadata.setScope(new Scope("test-scope"));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType(ResponseType.Value.CODE)));
		clientMetadata.setTokenEndpointAuthMethod(clientAuthenticationMethod);

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				ClientAuthenticationMethod.NONE.equals(clientAuthenticationMethod) ? null : new Secret("test-secret"));
	}

}
