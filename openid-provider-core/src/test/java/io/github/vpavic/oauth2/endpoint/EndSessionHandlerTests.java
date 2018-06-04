package io.github.vpavic.oauth2.endpoint;

import java.net.URL;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link EndSessionHandler}.
 */
class EndSessionHandlerTests {

	private Issuer issuer = new Issuer("http://example.com");

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private EndSessionHandler endSessionHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
	}

	@Test
	void construct_NullIssuer_ShouldThrowException() {
		assertThatThrownBy(() -> new EndSessionHandler(null, this.clientRepository))
				.isInstanceOf(NullPointerException.class).hasMessage("issuer must not be null");
	}

	@Test
	void construct_NullClientRepository_ShouldThrowException() {
		assertThatThrownBy(() -> new EndSessionHandler(this.issuer, null)).isInstanceOf(NullPointerException.class)
				.hasMessage("clientRepository must not be null");
	}

	@Test
	void handleLogoutSuccess_ValidRequest_ShouldReturnResponse() throws Exception {
		this.endSessionHandler = new EndSessionHandler(this.issuer, this.clientRepository);
		HTTPResponse response = this.endSessionHandler.handleLogoutSuccess(
				new HTTPRequest(HTTPRequest.Method.GET, new URL("http://example.com/end-session")),
				new SessionID("test"));

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("text/html");
		assertThat(response.getContent()).contains("window.location.href = 'http://example.com/login?logout';");
	}

	// TODO add more tests

}
