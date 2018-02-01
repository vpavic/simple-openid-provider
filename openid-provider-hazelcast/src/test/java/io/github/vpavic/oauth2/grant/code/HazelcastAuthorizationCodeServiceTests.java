package io.github.vpavic.oauth2.grant.code;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests for {@link HazelcastAuthorizationCodeService}.
 */
public class HazelcastAuthorizationCodeServiceTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private HazelcastInstance hazelcastInstance = mock(HazelcastInstance.class);

	private IMap codesMap = mock(IMap.class);

	private HazelcastAuthorizationCodeService authorizationCodeService;

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() {
		given(this.hazelcastInstance.getMap(anyString())).willReturn(this.codesMap);

		this.authorizationCodeService = new HazelcastAuthorizationCodeService(this.hazelcastInstance);
		this.authorizationCodeService.init();
	}

	@Test
	public void construct_NullHazelcastInstance_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("hazelcastInstance must not be null");

		new HazelcastAuthorizationCodeService(null);
	}

	@Test
	public void setMapName_Valid_ShouldSetMapName() throws IllegalAccessException {
		String mapName = "myMap";
		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setMapName(mapName);
		authorizationCodeService.init();

		assertThat(FieldUtils.readField(authorizationCodeService, "mapName", true)).isEqualTo(mapName);
	}

	@Test
	public void setMapName_Null_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("mapName must not be null");

		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setMapName(null);
	}

	@Test
	public void setTableName_Empty_ShouldThrowException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("mapName must not be empty");

		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setMapName(" ");
	}

	@Test
	public void setCodeLifetime_Valid_ShouldSetCodeLifetime() throws IllegalAccessException {
		Duration codeLifetime = Duration.ofMinutes(1);
		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setCodeLifetime(codeLifetime);
		authorizationCodeService.init();

		assertThat(FieldUtils.readField(authorizationCodeService, "codeLifetime", true)).isEqualTo(codeLifetime);
	}

	@Test
	public void setCodeLifetime_Null_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("codeLifetime must not be null");

		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setCodeLifetime(null);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void create_Valid_ShouldPut() {
		this.authorizationCodeService.create(AuthorizationCodeTestUtils.createAuthorizationCodeContext());

		verify(this.hazelcastInstance, times(1)).getMap(anyString());
		verify(this.codesMap, times(1)).put(anyString(), any(AuthorizationCodeContext.class), anyLong(),
				any(TimeUnit.class));
		verifyZeroInteractions(this.codesMap);
		verifyZeroInteractions(this.hazelcastInstance);
	}

	@Test
	public void create_NullContext_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("context must not be null");

		this.authorizationCodeService.create(null);
	}

	@Test
	public void consume_Valid_ShouldRemove() throws GeneralException {
		given(this.codesMap.remove(anyString()))
				.willReturn(AuthorizationCodeTestUtils.createAuthorizationCodeContext());

		this.authorizationCodeService.consume(new AuthorizationCode());

		verify(this.hazelcastInstance, times(1)).getMap(anyString());
		verify(this.codesMap, times(1)).remove(anyString());
		verifyZeroInteractions(this.codesMap);
		verifyZeroInteractions(this.hazelcastInstance);
	}

	@Test
	public void consume_Missing_ShouldThrowException() throws GeneralException {
		this.thrown.expect(GeneralException.class);
		this.thrown.expectMessage(OAuth2Error.INVALID_GRANT.getDescription());

		this.authorizationCodeService.consume(new AuthorizationCode());
	}

	@Test
	public void consume_NullCode_ShouldThrowException() throws GeneralException {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("code must not be null");

		this.authorizationCodeService.consume(null);
	}

}
