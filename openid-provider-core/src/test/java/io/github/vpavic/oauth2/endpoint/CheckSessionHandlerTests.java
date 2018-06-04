package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link CheckSessionHandler}.
 */
class CheckSessionHandlerTests {

	private CheckSessionHandler checkSessionHandler;

	@Test
	void construct_NullCookieName_ShouldThrowException() {
		assertThatThrownBy(() -> new CheckSessionHandler(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("cookieName must not be null");
	}

	@Test
	void checkSession_ValidCookieName_ShouldReturnIframe() {
		this.checkSessionHandler = new CheckSessionHandler("sid");
		HTTPResponse response = this.checkSessionHandler.checkSession();

		assertThat(response.getStatusCode()).isEqualTo(200);
		assertThat(response.getContentType().toString()).isEqualTo("text/html");
		assertThat(response.getContent()).contains("<title>Check Session Iframe</title>")
				.contains("var cookie = getCookie(\"sid\");");
	}

	// TODO add more tests

}
