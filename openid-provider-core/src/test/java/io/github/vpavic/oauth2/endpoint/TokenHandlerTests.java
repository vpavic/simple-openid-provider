package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.net.URL;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link TokenHandler}.
 */
class TokenHandlerTests {

	private AuthorizationCodeGrantHandler authorizationCodeGrantHandler = mock(AuthorizationCodeGrantHandler.class);

	private List<GrantHandler> grantHandlers = Collections.singletonList(this.authorizationCodeGrantHandler);

	private RefreshTokenStore refreshTokenStore = mock(RefreshTokenStore.class);

	private Issuer issuer = new Issuer("http://example.com");

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private TokenHandler tokenHandler;

	@BeforeEach
	void setUp() throws Exception {
		given(this.authorizationCodeGrantHandler.grantType()).willAnswer(invocation -> AuthorizationCodeGrant.class);
		given(this.authorizationCodeGrantHandler.grant(any())).willReturn(
				new Tokens(new BearerAccessToken("test-access-token"), new RefreshToken("test-refresh-token")));
		reset(this.refreshTokenStore);
		reset(this.clientRepository);
	}

	@Test
	void construct_NullGrantHandlers_ShouldThrowException() {
		assertThatThrownBy(() -> new TokenHandler(null, this.refreshTokenStore, this.issuer, this.clientRepository))
				.isInstanceOf(NullPointerException.class).hasMessage("grantHandlers must not be null");
	}

	@Test
	void construct_EmptyGrantHandlers_ShouldThrowException() {
		assertThatThrownBy(() -> new TokenHandler(Collections.emptyList(), this.refreshTokenStore, this.issuer,
				this.clientRepository)).isInstanceOf(IllegalArgumentException.class)
						.hasMessage("grantHandlers must not be empty");
	}

	@Test
	void construct_NullRefreshTokenStore_ShouldThrowException() {
		assertThatThrownBy(() -> new TokenHandler(this.grantHandlers, null, this.issuer, this.clientRepository))
				.isInstanceOf(NullPointerException.class).hasMessage("refreshTokenStore must not be null");
	}

	@Test
	void construct_NullIssuer_ShouldThrowException() {
		assertThatThrownBy(
				() -> new TokenHandler(this.grantHandlers, this.refreshTokenStore, null, this.clientRepository))
						.isInstanceOf(NullPointerException.class).hasMessage("issuer must not be null");
	}

	@Test
	void construct_NullClientRepository_ShouldThrowException() {
		assertThatThrownBy(() -> new TokenHandler(this.grantHandlers, this.refreshTokenStore, this.issuer, null))
				.isInstanceOf(NullPointerException.class).hasMessage("clientRepository must not be null");
	}

	@Test
	void handleTokenRequest_GetRequest_ShouldReturnError() throws Exception {
		this.tokenHandler = new TokenHandler(this.grantHandlers, this.refreshTokenStore, this.issuer,
				this.clientRepository);
		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://example.com/end-session"));
		HTTPResponse response = this.tokenHandler.handleTokenRequest(request);

		assertThat(response.getStatusCode()).isEqualTo(400);
		assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
		DocumentContext ctx = JsonPath.parse(response.getContent());
		assertThat(ctx.read("$.error", String.class)).isEqualTo("invalid_request");
		assertThat(ctx.read("$.error_description", String.class)).isEqualTo("Invalid request");
	}

	@Test
	void handleTokenRequest_PostRequestWithoutContentType_ShouldReturnError() throws Exception {
		this.tokenHandler = new TokenHandler(this.grantHandlers, this.refreshTokenStore, this.issuer,
				this.clientRepository);
		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://example.com/end-session"));
		HTTPResponse response = this.tokenHandler.handleTokenRequest(request);

		assertThat(response.getStatusCode()).isEqualTo(400);
		assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
		DocumentContext ctx = JsonPath.parse(response.getContent());
		assertThat(ctx.read("$.error", String.class)).isEqualTo("invalid_request");
		assertThat(ctx.read("$.error_description", String.class)).isEqualTo("Invalid request");
	}

	@Test
	void handleTokenRequest_PostRequestWithoutParams_ShouldReturnError() throws Exception {
		this.tokenHandler = new TokenHandler(this.grantHandlers, this.refreshTokenStore, this.issuer,
				this.clientRepository);
		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://example.com/end-session"));
		request.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		HTTPResponse response = this.tokenHandler.handleTokenRequest(request);

		assertThat(response.getStatusCode()).isEqualTo(400);
		assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
		DocumentContext ctx = JsonPath.parse(response.getContent());
		assertThat(ctx.read("$.error", String.class)).isEqualTo("invalid_request");
		assertThat(ctx.read("$.error_description", String.class))
				.isEqualTo("Invalid request: Missing \"grant_type\" parameter");
	}

	@Test
	void handleTokenRequest_ValidPostRequest_ShouldReturnError() throws Exception {
		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.tokenHandler = new TokenHandler(this.grantHandlers, this.refreshTokenStore, this.issuer,
				this.clientRepository);
		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://example.com/end-session"));
		request.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		request.setAuthorization("Basic " + Base64.getEncoder().encodeToString("test-client:test-secret".getBytes()));
		request.setQuery("grant_type=authorization_code&code=qwerty");
		HTTPResponse response = this.tokenHandler.handleTokenRequest(request);

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
		DocumentContext ctx = JsonPath.parse(response.getContent());
		assertThat(ctx.read("$.access_token", String.class)).isEqualTo("test-access-token");
		assertThat(ctx.read("$.refresh_token", String.class)).isEqualTo("test-refresh-token");
		assertThat(ctx.read("$.token_type", String.class)).isEqualTo("Bearer");
	}

	// TODO add more tests

	private static OIDCClientInformation client(ResponseType responseType, Scope scope) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com"));
		clientMetadata.setScope(scope);
		clientMetadata.setResponseTypes(Collections.singleton(responseType));

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				new Secret("test-secret"));
	}

	private static OIDCClientInformation authCodeClient() {
		return client(new ResponseType(ResponseType.Value.CODE), new Scope(OIDCScopeValue.OPENID));
	}

}
