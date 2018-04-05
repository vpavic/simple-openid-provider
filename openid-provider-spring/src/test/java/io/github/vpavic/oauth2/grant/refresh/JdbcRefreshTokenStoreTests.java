package io.github.vpavic.oauth2.grant.refresh;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.DirectFieldAccessor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.AdditionalMatchers.and;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests for {@link JdbcRefreshTokenStore}.
 */
public class JdbcRefreshTokenStoreTests {

	private JdbcOperations jdbcOperations = mock(JdbcOperations.class);

	private JdbcRefreshTokenStore refreshTokenStore;

	@BeforeEach
	public void setUp() {
		this.refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
		this.refreshTokenStore.init();
	}

	@Test
	public void construct_NullJdbcOperations_ShouldThrowException() {
		assertThatThrownBy(() -> new JdbcRefreshTokenStore(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("jdbcOperations must not be null");
	}

	@Test
	public void setTableName_Valid_ShouldSetTableName() {
		String tableName = "my_table";
		JdbcRefreshTokenStore refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
		refreshTokenStore.setTableName(tableName);
		refreshTokenStore.init();

		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementInsert"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementSelectByToken"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore)
				.getPropertyValue("statementSelectByClientIdAndSubject")).contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementDeleteByToken"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementDeleteExpired"))
				.contains(tableName);
	}

	@Test
	public void setTableName_Null_ShouldThrowException() {
		assertThatThrownBy(() -> {
			JdbcRefreshTokenStore refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
			refreshTokenStore.setTableName(null);
		}).isInstanceOf(NullPointerException.class).hasMessage("tableName must not be null");
	}

	@Test
	public void setTableName_Empty_ShouldThrowException() {
		assertThatThrownBy(() -> {
			JdbcRefreshTokenStore refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
			refreshTokenStore.setTableName(" ");
		}).isInstanceOf(IllegalArgumentException.class).hasMessage("tableName must not be empty");
	}

	@Test
	public void save_Valid_ShouldInsert() {
		given(this.jdbcOperations.update(anyString(), any(PreparedStatementSetter.class))).willReturn(0);

		this.refreshTokenStore.save(RefreshTokenTestUtils.createRefreshTokenContext(null));

		verify(this.jdbcOperations, times(1)).update(startsWith("INSERT"), any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void save_NullContext_ShouldThrowException() {
		assertThatThrownBy(() -> this.refreshTokenStore.save(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("context must not be null");

		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void load_Existing_ShouldReturnClient() throws GeneralException {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(null);
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString())).willReturn(context);

		assertThat(this.refreshTokenStore.load(context.getRefreshToken())).isNotNull();
		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(context.getRefreshToken().getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void load_Missing_ShouldThrowException() {
		RefreshToken token = new RefreshToken();
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString()))
				.willThrow(EmptyResultDataAccessException.class);

		assertThatThrownBy(() -> this.refreshTokenStore.load(token)).isInstanceOf(GeneralException.class)
				.hasMessage(OAuth2Error.INVALID_GRANT.getDescription());

		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(token.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void load_Expired_ShouldThrowException() {
		RefreshTokenContext context = RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1));
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString())).willReturn(context);

		assertThatThrownBy(() -> this.refreshTokenStore.load(context.getRefreshToken()))
				.isInstanceOf(GeneralException.class).hasMessage(OAuth2Error.INVALID_GRANT.getDescription());

		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(context.getRefreshToken().getValue()));
		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("WHERE token = ?")),
				any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void load_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.refreshTokenStore.load(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("refreshToken must not be null");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void findByClientIdAndSubject_Existing_ShouldReturnClient() {
		ClientID clientId = new ClientID(UUID.randomUUID().toString());
		Subject subject = new Subject(UUID.randomUUID().toString());
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString(), anyString()))
				.willReturn(RefreshTokenTestUtils.createRefreshTokenContext(null));

		assertThat(this.refreshTokenStore.findByClientIdAndSubject(clientId, subject)).isNotNull();
		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(clientId.getValue()), eq(subject.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void findByClientIdAndSubject_Missing_ShouldReturnNull() {
		ClientID clientId = new ClientID(UUID.randomUUID().toString());
		Subject subject = new Subject(UUID.randomUUID().toString());
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString(), anyString()))
				.willThrow(EmptyResultDataAccessException.class);

		assertThat(this.refreshTokenStore.findByClientIdAndSubject(clientId, subject)).isNull();
		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(clientId.getValue()), eq(subject.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void findByClientIdAndSubject_Expired_ShouldReturnNull() {
		ClientID clientId = new ClientID(UUID.randomUUID().toString());
		Subject subject = new Subject(UUID.randomUUID().toString());
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString(), anyString()))
				.willReturn(RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1)));

		assertThat(this.refreshTokenStore.findByClientIdAndSubject(clientId, subject)).isNull();
		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(clientId.getValue()), eq(subject.getValue()));
		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("WHERE token = ?")),
				any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void findByClientIdAndSubject_NullClientId_ShouldThrowException() {
		assertThatThrownBy(
				() -> this.refreshTokenStore.findByClientIdAndSubject(null, new Subject(UUID.randomUUID().toString())))
						.isInstanceOf(NullPointerException.class).hasMessage("clientId must not be null");
	}

	@Test
	public void findByClientIdAndSubject_NullSubject_ShouldThrowException() {
		assertThatThrownBy(
				() -> this.refreshTokenStore.findByClientIdAndSubject(new ClientID(UUID.randomUUID().toString()), null))
						.isInstanceOf(NullPointerException.class).hasMessage("subject must not be null");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void findBySubject_Existing_ShouldReturnClientList() {
		Subject subject = new Subject(UUID.randomUUID().toString());
		given(this.jdbcOperations.query(anyString(), any(RowMapper.class), anyString()))
				.willReturn(Collections.singletonList(RefreshTokenTestUtils.createRefreshTokenContext(null)));

		assertThat(this.refreshTokenStore.findBySubject(subject)).hasSize(1);
		verify(this.jdbcOperations, times(1)).query(startsWith("SELECT"), any(RowMapper.class), eq(subject.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void findBySubject_Missing_ShouldReturnEmptyList() {
		Subject subject = new Subject(UUID.randomUUID().toString());
		given(this.jdbcOperations.query(anyString(), any(RowMapper.class), anyString()))
				.willReturn(Collections.emptyList());

		assertThat(this.refreshTokenStore.findBySubject(subject)).isEmpty();
		verify(this.jdbcOperations, times(1)).query(startsWith("SELECT"), any(RowMapper.class), eq(subject.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void findBySubject_Expired_ShouldReturnEmptyList() {
		Subject subject = new Subject(UUID.randomUUID().toString());
		given(this.jdbcOperations.query(anyString(), any(RowMapper.class), anyString())).willReturn(Collections
				.singletonList(RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1))));

		assertThat(this.refreshTokenStore.findBySubject(subject)).isEmpty();
		verify(this.jdbcOperations, times(1)).query(startsWith("SELECT"), any(RowMapper.class), eq(subject.getValue()));
		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("WHERE token = ?")),
				any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void findBySubject_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.refreshTokenStore.findBySubject(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("subject must not be null");
	}

	@Test
	public void revoke_Valid_ShouldReturnNull() {
		this.refreshTokenStore.revoke(new RefreshToken());

		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("WHERE token = ?")),
				any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void revoke_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.refreshTokenStore.revoke(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("refreshToken must not be null");
	}

	@Test
	public void revokeAllForSubject_Valid_ShouldReturnNull() {
		Subject subject = new Subject(UUID.randomUUID().toString());
		this.refreshTokenStore.revokeAllForSubject(subject);

		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("WHERE subject = ?")),
				eq(subject.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void revokeAllForSubject_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.refreshTokenStore.revokeAllForSubject(null))
				.isInstanceOf(NullPointerException.class).hasMessage("subject must not be null");
	}

	@Test
	public void cleanExpiredTokens_Na_ShouldReturnNull() {
		this.refreshTokenStore.cleanExpiredTokens();

		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("AND expiry < ?")),
				any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

}
