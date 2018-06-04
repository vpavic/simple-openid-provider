package io.github.vpavic.oauth2.grant.password;

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
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
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.RefreshTokenService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalAnswers.returnsSecondArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link ResourceOwnerPasswordCredentialsGrantHandler}.
 */
class ResourceOwnerPasswordCredentialsGrantHandlerTests {

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private AccessTokenService accessTokenService = mock(AccessTokenService.class);

	private RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);

	private ScopeResolver scopeResolver = mock(ScopeResolver.class);

	private PasswordAuthenticationHandler passwordAuthenticationHandler = mock(PasswordAuthenticationHandler.class);

	private ResourceOwnerPasswordCredentialsGrantHandler grantHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
		reset(this.accessTokenService);
		reset(this.refreshTokenService);
		reset(this.scopeResolver);
		reset(this.passwordAuthenticationHandler);
	}

	@Test
	void grant_ValidBasicAuthRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		Subject subject = new Subject("test-user");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.passwordAuthenticationHandler.authenticate(any(ResourceOwnerPasswordCredentialsGrant.class)))
				.willReturn(subject);
		given(this.scopeResolver.resolve(eq(subject), eq(scope), any(OIDCClientMetadata.class)))
				.willAnswer(returnsSecondArg());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		this.grantHandler = new ResourceOwnerPasswordCredentialsGrantHandler(this.clientRepository,
				this.accessTokenService, this.refreshTokenService, this.scopeResolver,
				this.passwordAuthenticationHandler);

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new ResourceOwnerPasswordCredentialsGrant(subject.getValue(), new Secret("test-password")), scope);
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(Tokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
	}

	@Test
	void grant_ValidPostAuthRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		Subject subject = new Subject("test-user");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.passwordAuthenticationHandler.authenticate(any(ResourceOwnerPasswordCredentialsGrant.class)))
				.willReturn(subject);
		given(this.scopeResolver.resolve(eq(subject), eq(scope), any(OIDCClientMetadata.class)))
				.willAnswer(returnsSecondArg());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		this.grantHandler = new ResourceOwnerPasswordCredentialsGrantHandler(this.clientRepository,
				this.accessTokenService, this.refreshTokenService, this.scopeResolver,
				this.passwordAuthenticationHandler);

		ClientSecretPost clientAuth = new ClientSecretPost(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new ResourceOwnerPasswordCredentialsGrant(subject.getValue(), new Secret("test-password")), scope);
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
		clientMetadata.setScope(new Scope(OIDCScopeValue.OPENID));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType(ResponseType.Value.CODE)));
		clientMetadata.setTokenEndpointAuthMethod(clientAuthenticationMethod);

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				ClientAuthenticationMethod.NONE.equals(clientAuthenticationMethod) ? null : new Secret("test-secret"));
	}

}
