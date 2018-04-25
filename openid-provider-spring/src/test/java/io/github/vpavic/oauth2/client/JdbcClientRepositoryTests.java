package io.github.vpavic.oauth2.client;

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.DirectFieldAccessor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.AdditionalMatchers.and;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests for {@link JdbcClientRepository}.
 */
class JdbcClientRepositoryTests {

	private JdbcOperations jdbcOperations = mock(JdbcOperations.class);

	private JdbcClientRepository clientRepository;

	@BeforeEach
	void setUp() {
		this.clientRepository = new JdbcClientRepository(this.jdbcOperations);
		this.clientRepository.init();
	}

	@Test
	void construct_NullJdbcOperations_ShouldThrowException() {
		assertThatThrownBy(() -> new JdbcClientRepository(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("jdbcOperations must not be null");
	}

	@Test
	void setTableName_Valid_ShouldSetTableName() {
		String tableName = "my_table";
		JdbcClientRepository clientRepository = new JdbcClientRepository(this.jdbcOperations);
		clientRepository.setTableName(tableName);
		clientRepository.init();

		assertThat((String) new DirectFieldAccessor(clientRepository).getPropertyValue("statementInsert"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(clientRepository).getPropertyValue("statementSelectById"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(clientRepository).getPropertyValue("statementSelectAll"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(clientRepository).getPropertyValue("statementUpdate"))
				.contains(tableName);
		assertThat((String) new DirectFieldAccessor(clientRepository).getPropertyValue("statementDelete"))
				.contains(tableName);
	}

	@Test
	void setTableName_Null_ShouldThrowException() {
		assertThatThrownBy(() -> {
			JdbcClientRepository clientRepository = new JdbcClientRepository(this.jdbcOperations);
			clientRepository.setTableName(null);
		}).isInstanceOf(NullPointerException.class).hasMessage("tableName must not be null");
	}

	@Test
	void setTableName_Empty_ShouldThrowException() {
		assertThatThrownBy(() -> {
			JdbcClientRepository clientRepository = new JdbcClientRepository(this.jdbcOperations);
			clientRepository.setTableName(" ");
		}).isInstanceOf(IllegalArgumentException.class).hasMessage("tableName must not be empty");
	}

	@Test
	void save_New_ShouldInsert() {
		given(this.jdbcOperations.update(anyString(), any(PreparedStatementSetter.class))).willReturn(0);

		this.clientRepository.save(ClientTestUtils.createClient());

		verify(this.jdbcOperations).update(startsWith("UPDATE"), any(PreparedStatementSetter.class));
		verify(this.jdbcOperations).update(startsWith("INSERT"), any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	void save_Existing_ShouldUpdate() {
		given(this.jdbcOperations.update(anyString(), any(PreparedStatementSetter.class))).willReturn(1);

		this.clientRepository.save(ClientTestUtils.createClient());

		verify(this.jdbcOperations).update(startsWith("UPDATE"), any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	void save_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.clientRepository.save(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("client must not be null");

		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	void findById_Existing_ShouldReturnClient() {
		OIDCClientInformation client = ClientTestUtils.createClient();
		ClientID id = client.getID();
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString())).willReturn(client);

		assertThat(this.clientRepository.findById(id)).isNotNull();
		verify(this.jdbcOperations).queryForObject(and(startsWith("SELECT"), endsWith("WHERE id = ?")),
				any(RowMapper.class), eq(id.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	void findById_Missing_ShouldReturnNull() {
		ClientID id = new ClientID(UUID.randomUUID().toString());
		given(this.jdbcOperations.queryForObject(anyString(), any(RowMapper.class), anyString())).willReturn(null);

		assertThat(this.clientRepository.findById(id)).isNull();
		verify(this.jdbcOperations).queryForObject(and(startsWith("SELECT"), endsWith("WHERE id = ?")),
				any(RowMapper.class), eq(id.getValue()));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	void findById_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.clientRepository.findById(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("id must not be null");
	}

	@Test
	@SuppressWarnings("unchecked")
	void findAll_Na_ShouldReturnClients() {
		given(this.jdbcOperations.query(anyString(), any(RowMapper.class)))
				.willReturn(Arrays.asList(ClientTestUtils.createClient(), ClientTestUtils.createClient()));

		assertThat(this.clientRepository.findAll()).hasSize(2);
		verify(this.jdbcOperations).query(and(startsWith("SELECT"), not(endsWith("WHERE id = ?"))),
				any(RowMapper.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	@SuppressWarnings("unchecked")
	void findAll_Na_ShouldReturnEmptyList() {
		given(this.jdbcOperations.query(anyString(), any(RowMapper.class))).willReturn(Collections.emptyList());

		assertThat(this.clientRepository.findAll()).isEmpty();
		verify(this.jdbcOperations).query(and(startsWith("SELECT"), not(endsWith("WHERE id = ?"))),
				any(RowMapper.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	void deleteById_Valid_ShouldReturnNull() {
		this.clientRepository.deleteById(new ClientID(UUID.randomUUID().toString()));

		verify(this.jdbcOperations).update(startsWith("DELETE"), any(PreparedStatementSetter.class));
		verifyZeroInteractions(this.jdbcOperations);
	}

	@Test
	void deleteById_Null_ShouldThrowException() {
		assertThatThrownBy(() -> this.clientRepository.deleteById(null)).isInstanceOf(NullPointerException.class)
				.hasMessage("id must not be null");
	}

}
