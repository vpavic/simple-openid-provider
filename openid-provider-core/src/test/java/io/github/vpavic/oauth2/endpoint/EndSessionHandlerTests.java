package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link EndSessionHandler}.
 */
class EndSessionHandlerTests {

	private Issuer issuer = new Issuer("http://example.com");

	private JwkSetLoader jwkSetLoader = mock(JwkSetLoader.class);

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private EndSessionHandler endSessionHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
	}

	@Test
	void construct_NullIssuer_ShouldThrowException() {
		assertThatThrownBy(() -> new EndSessionHandler(null, this.jwkSetLoader, this.clientRepository))
				.isInstanceOf(NullPointerException.class).hasMessage("issuer must not be null");
	}

	@Test
	void construct_NullJwkSetLoader_ShouldThrowException() {
		assertThatThrownBy(() -> new EndSessionHandler(this.issuer, null, this.clientRepository))
				.isInstanceOf(NullPointerException.class).hasMessage("jwkSetLoader must not be null");
	}

	@Test
	void construct_NullClientRepository_ShouldThrowException() {
		assertThatThrownBy(() -> new EndSessionHandler(this.issuer, this.jwkSetLoader, null))
				.isInstanceOf(NullPointerException.class).hasMessage("clientRepository must not be null");
	}

	@Test
	void handleLogoutSuccess_NoParams_ShouldReturnSuccessResponse() throws Exception {
		this.endSessionHandler = new EndSessionHandler(this.issuer, this.jwkSetLoader, this.clientRepository);

		HTTPResponse response = this.endSessionHandler.handleLogoutSuccess(
				new HTTPRequest(Method.GET, new URL("http://example.com/end-session")), new SessionID("test-session"));

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("text/html");
		assertThat(response.getContent()).contains("window.location.href = 'http://example.com/login?logout';");
	}

	@Test
	void handleLogoutSuccess_WithPostLogoutUriAndNoIdToken_ShouldReturnSuccessResponse() throws Exception {
		this.endSessionHandler = new EndSessionHandler(this.issuer, this.jwkSetLoader, this.clientRepository);

		HTTPRequest request = new HTTPRequest(Method.GET, new URL("http://example.com/end-session"));
		request.setQuery("post_logout_redirect_uri=http://example.com");
		HTTPResponse response = this.endSessionHandler.handleLogoutSuccess(request, new SessionID("test-session"));

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("text/html");
		assertThat(response.getContent()).contains("window.location.href = 'http://example.com/login?logout';");
	}

	@Test
	void handleLogoutSuccess_WithInvalidIdToken_ShouldReturnErrorResponse() throws Exception {
		this.endSessionHandler = new EndSessionHandler(this.issuer, this.jwkSetLoader, this.clientRepository);

		HTTPRequest request = new HTTPRequest(Method.GET, new URL("http://example.com/end-session"));
		request.setQuery("id_token_hint=invalid-token&post_logout_redirect_uri=http://example.com");
		HTTPResponse response = this.endSessionHandler.handleLogoutSuccess(request, new SessionID("test-session"));

		assertThat(response.getStatusCode()).isEqualTo(400);
	}

	@Test
	void handleLogoutSuccess_IdTokenAndPostLogoutUri_ShouldReturnSuccessResponse() throws Exception {
		RSAKey rsaKey = generateKey();
		ClientID clientId = new ClientID("test-client");
		Instant now = Instant.now();

		given(this.jwkSetLoader.load()).willReturn(new JWKSet(rsaKey));
		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(Collections.singleton(URI.create("http://example.com"))));
		this.endSessionHandler = new EndSessionHandler(this.issuer, this.jwkSetLoader, this.clientRepository);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(this.issuer, new Subject("test-user"),
				Collections.singletonList(new Audience(clientId.getValue())), Date.from(now.plusSeconds(60)),
				Date.from(now));
		JWTAssertionDetails details = JWTAssertionDetails.parse(idTokenClaimsSet.toJWTClaimsSet());
		SignedJWT jwt = JWTAssertionFactory.create(details, JWSAlgorithm.RS256, rsaKey.toRSAPrivateKey(),
				rsaKey.getKeyID(), null);
		HTTPRequest request = new HTTPRequest(Method.GET, new URL("http://example.com/end-session"));
		request.setQuery("id_token_hint=" + jwt.serialize() + "&post_logout_redirect_uri=http://example.com");
		HTTPResponse response = this.endSessionHandler.handleLogoutSuccess(request, new SessionID("test-session"));

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("text/html");
		assertThat(response.getContent()).contains("window.location.href = 'http://example.com';");
	}

	@Test
	void handleLogoutSuccess_IdTokenAndPostLogoutUriAndNoRegisteredUri_ShouldReturnSuccessResponse() throws Exception {
		RSAKey rsaKey = generateKey();
		ClientID clientId = new ClientID("test-client");
		Instant now = Instant.now();

		given(this.jwkSetLoader.load()).willReturn(new JWKSet(rsaKey));
		given(this.clientRepository.findById(eq(clientId))).willReturn(client(Collections.emptySet()));
		this.endSessionHandler = new EndSessionHandler(this.issuer, this.jwkSetLoader, this.clientRepository);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(this.issuer, new Subject("test-user"),
				Collections.singletonList(new Audience(clientId.getValue())), Date.from(now.plusSeconds(60)),
				Date.from(now));
		JWTAssertionDetails details = JWTAssertionDetails.parse(idTokenClaimsSet.toJWTClaimsSet());
		SignedJWT jwt = JWTAssertionFactory.create(details, JWSAlgorithm.RS256, rsaKey.toRSAPrivateKey(),
				rsaKey.getKeyID(), null);
		HTTPRequest request = new HTTPRequest(Method.GET, new URL("http://example.com/end-session"));
		request.setQuery("id_token_hint=" + jwt.serialize() + "&post_logout_redirect_uri=http://example.com");
		HTTPResponse response = this.endSessionHandler.handleLogoutSuccess(request, new SessionID("test-session"));

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("text/html");
		assertThat(response.getContent()).contains("window.location.href = 'http://example.com/login?logout';");
	}

	private static RSAKey generateKey() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(512);
			KeyPair kp = generator.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

			// @formatter:off
			return new RSAKey.Builder(publicKey)
					.privateKey(privateKey)
					.algorithm(JWSAlgorithm.RS256)
					.keyID("test-key")
					.build();
			// @formatter:on
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private static OIDCClientInformation client(Set<URI> postLogoutRedirectUris) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com/cb"));
		clientMetadata.setScope(new Scope(OIDCScopeValue.OPENID));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType(ResponseType.Value.CODE)));
		clientMetadata.setPostLogoutRedirectionURIs(postLogoutRedirectUris);

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				new Secret("test-secret"));
	}

}
