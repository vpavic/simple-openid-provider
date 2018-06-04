package io.github.vpavic.oauth2.grant.client;

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
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
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.AccessTokenService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalAnswers.returnsSecondArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link ClientCredentialsGrantHandler}.
 */
class ClientCredentialsGrantHandlerTests {

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private AccessTokenService accessTokenService = mock(AccessTokenService.class);

	private ScopeResolver scopeResolver = mock(ScopeResolver.class);

	private ClientCredentialsGrantHandler grantHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
		reset(this.accessTokenService);
		reset(this.scopeResolver);
	}

	@Test
	void grant_ValidBasicAuthRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		Scope scope = new Scope("test-scope");
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.scopeResolver.resolve(eq(new Subject(clientId.getValue())), eq(scope),
				any(OIDCClientMetadata.class))).willAnswer(returnsSecondArg());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		this.grantHandler = new ClientCredentialsGrantHandler(this.clientRepository, this.scopeResolver,
				this.accessTokenService);

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/tokens"), clientAuth,
				new ClientCredentialsGrant(), scope);
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(Tokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
	}

	@Test
	void grant_ValidPostAuthRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		Scope scope = new Scope("test-scope");
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.scopeResolver.resolve(eq(new Subject(clientId.getValue())), eq(scope),
				any(OIDCClientMetadata.class))).willAnswer(returnsSecondArg());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		this.grantHandler = new ClientCredentialsGrantHandler(this.clientRepository, this.scopeResolver,
				this.accessTokenService);

		ClientSecretPost clientAuth = new ClientSecretPost(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/tokens"), clientAuth,
				new ClientCredentialsGrant(), scope);
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
