package io.github.vpavic.oauth2.endpoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.token.AccessTokenService;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link UserInfoHandler}.
 */
class UserInfoHandlerTests {

	private AccessTokenService accessTokenService = mock(AccessTokenService.class);

	private ClaimSource claimSource = mock(ClaimSource.class);

	private UserInfoHandler userInfoHandler;

	@BeforeEach
	void setUp() {
		reset(this.accessTokenService);
		reset(this.claimSource);
	}

	@Test
	void construct_WithNullAccessTokenService_ShouldThrowException() {
		assertThatThrownBy(() -> new UserInfoHandler(null, this.claimSource)).isInstanceOf(NullPointerException.class)
				.hasMessage("accessTokenService must not be null");
	}

	@Test
	void construct_WithNullClaimSource_ShouldThrowException() {
		assertThatThrownBy(() -> new UserInfoHandler(this.accessTokenService, null))
				.isInstanceOf(NullPointerException.class).hasMessage("claimSource must not be null");
	}

	// TODO add more tests

}
