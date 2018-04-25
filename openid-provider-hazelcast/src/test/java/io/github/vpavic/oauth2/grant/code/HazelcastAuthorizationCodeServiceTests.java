package io.github.vpavic.oauth2.grant.code;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests for {@link HazelcastAuthorizationCodeService}.
 */
class HazelcastAuthorizationCodeServiceTests {

	private HazelcastInstance hazelcastInstance = mock(HazelcastInstance.class);

	private IMap codesMap = mock(IMap.class);

	private HazelcastAuthorizationCodeService authorizationCodeService;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp() {
		given(this.hazelcastInstance.getMap(anyString())).willReturn(this.codesMap);

		this.authorizationCodeService = new HazelcastAuthorizationCodeService(this.hazelcastInstance);
		this.authorizationCodeService.init();
	}

	@Test
	void construct_NullHazelcastInstance_ShouldThrowException() {
		assertThatThrownBy(() -> new HazelcastAuthorizationCodeService(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("hazelcastInstance must not be null");
	}

	@Test
	void setMapName_Valid_ShouldSetMapName() throws IllegalAccessException {
		String mapName = "myMap";
		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setMapName(mapName);
		authorizationCodeService.init();

		assertThat(FieldUtils.readField(authorizationCodeService, "mapName", true)).isEqualTo(mapName);
	}

	@Test
	void setMapName_Null_ShouldThrowException() {
		assertThatThrownBy(() -> {
			HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
					this.hazelcastInstance);
			authorizationCodeService.setMapName(null);
		}).isInstanceOf(NullPointerException.class).hasMessage("mapName must not be null");
	}

	@Test
	void setTableName_Empty_ShouldThrowException() {
		assertThatThrownBy(() -> {
			HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
					this.hazelcastInstance);
			authorizationCodeService.setMapName(" ");
		}).isInstanceOf(IllegalArgumentException.class).hasMessage("mapName must not be empty");
	}

	@Test
	void setCodeLifetime_Valid_ShouldSetCodeLifetime() throws IllegalAccessException {
		Duration codeLifetime = Duration.ofMinutes(1);
		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setCodeLifetime(codeLifetime);
		authorizationCodeService.init();

		assertThat(FieldUtils.readField(authorizationCodeService, "codeLifetime", true)).isEqualTo(codeLifetime);
	}

	@Test
	void setCodeLifetime_Null_ShouldThrowException() {
		assertThatThrownBy(() -> {
			HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
					this.hazelcastInstance);
			authorizationCodeService.setCodeLifetime(null);
		}).isInstanceOf(NullPointerException.class).hasMessage("codeLifetime must not be null");
	}

	@Test
	@SuppressWarnings("unchecked")
	void create_Valid_ShouldPut() {
		this.authorizationCodeService.create(AuthorizationCodeTestUtils.createAuthorizationCodeContext());

		verify(this.hazelcastInstance).getMap(anyString());
		verify(this.codesMap).put(anyString(), any(AuthorizationCodeContext.class), anyLong(), any(TimeUnit.class));
		verifyZeroInteractions(this.codesMap);
		verifyZeroInteractions(this.hazelcastInstance);
	}

	@Test
	void create_NullContext_ShouldThrowException() {
		assertThatThrownBy(() -> this.authorizationCodeService.create(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("context must not be null");
	}

	@Test
	void consume_Valid_ShouldRemove() throws GeneralException {
		given(this.codesMap.remove(anyString()))
				.willReturn(AuthorizationCodeTestUtils.createAuthorizationCodeContext());

		this.authorizationCodeService.consume(new AuthorizationCode());

		verify(this.hazelcastInstance).getMap(anyString());
		verify(this.codesMap).remove(anyString());
		verifyZeroInteractions(this.codesMap);
		verifyZeroInteractions(this.hazelcastInstance);
	}

	@Test
	void consume_Missing_ShouldThrowException() {
		assertThatThrownBy(() -> this.authorizationCodeService.consume(new AuthorizationCode()))
				.isInstanceOf(GeneralException.class).hasMessage(OAuth2Error.INVALID_GRANT.getDescription());
	}

	@Test
	void consume_NullCode_ShouldThrowException() {
		assertThatThrownBy(() -> this.authorizationCodeService.consume(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("code must not be null");
	}

}
