package io.github.vpavic.oauth2.grant.refresh;

import java.time.Instant;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.DirectFieldAccessor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;

import static org.assertj.core.api.Assertions.assertThat;
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
 *
 * @author Vedran Pavic
 */
public class JdbcRefreshTokenStoreTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private JdbcOperations jdbcOperations = mock(JdbcOperations.class);

	private JdbcRefreshTokenStore refreshTokenStore;

	@Before
	public void setUp() {
		this.refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
		this.refreshTokenStore.init();
	}

	@Test
	public void construct_NullJdbcOperations_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("jdbcOperations must not be null");

		new JdbcRefreshTokenStore(null);
	}

	@Test
	public void setTableName_Valid_ShouldSetTableName() {
		String tableName = "my_table";
		JdbcRefreshTokenStore refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
		refreshTokenStore.setTableName(tableName);
		refreshTokenStore.init();

		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementInsert"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementSelect"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementDelete"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(refreshTokenStore).getPropertyValue("statementDeleteExpired"))
				.contains(tableName);
	}

	@Test
	public void setTableName_Null_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("tableName must not be null");

		JdbcRefreshTokenStore refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
		refreshTokenStore.setTableName(null);
	}

	@Test
	public void setTableName_Empty_ShouldThrowException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("tableName must not be empty");

		JdbcRefreshTokenStore refreshTokenStore = new JdbcRefreshTokenStore(this.jdbcOperations);
		refreshTokenStore.setTableName(" ");
	}

	@Test
	public void save_Valid_ShouldInsert() {
		given(this.jdbcOperations.update(anyString(), any(PreparedStatementSetter.class))).willReturn(0);

		this.refreshTokenStore.save(new RefreshToken(), RefreshTokenTestUtils.createRefreshTokenContext(null));

		verify(this.jdbcOperations, times(1)).update(startsWith("INSERT"), any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void save_NullAccessToken_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("refreshToken must not be null");

		this.refreshTokenStore.save(null, RefreshTokenTestUtils.createRefreshTokenContext(null));

		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void save_NullContext_ShouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("context must not be null");

		this.refreshTokenStore.save(new RefreshToken(), null);

		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void load_Existing_ShouldReturnClient() throws GeneralException {
		RefreshToken refreshToken = new RefreshToken();
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString()))
				.willReturn(RefreshTokenTestUtils.createRefreshTokenContext(null));

		assertThat(this.refreshTokenStore.load(refreshToken)).isNotNull();
		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(refreshToken.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void load_Missing_ShouldThrowException() throws GeneralException {
		RefreshToken refreshToken = new RefreshToken();
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString())).willReturn(null);
		this.thrown.expect(GeneralException.class);
		this.thrown.expectMessage(OAuth2Error.INVALID_GRANT.getDescription());

		this.refreshTokenStore.load(refreshToken);

		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(refreshToken.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void load_Expired_ShouldThrowException() throws GeneralException {
		RefreshToken refreshToken = new RefreshToken();
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString()))
				.willReturn(RefreshTokenTestUtils.createRefreshTokenContext(Instant.now().minusSeconds(1)));
		this.thrown.expect(GeneralException.class);
		this.thrown.expectMessage(OAuth2Error.INVALID_GRANT.getDescription());

		this.refreshTokenStore.load(refreshToken);

		verify(this.jdbcOperations, times(1)).queryForObject(startsWith("SELECT"), any(RowMapper.class),
				eq(refreshToken.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	public void load_Null_ShouldThrowException() throws GeneralException {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("refreshToken must not be null");

		this.refreshTokenStore.load(null);
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
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("refreshToken must not be null");

		this.refreshTokenStore.revoke(null);
	}

	@Test
	public void cleanExpiredTokens_Na_ShouldReturnNull() {
		this.refreshTokenStore.cleanExpiredTokens();

		verify(this.jdbcOperations, times(1)).update(and(startsWith("DELETE"), endsWith("AND expiry < ?")),
				any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

}
