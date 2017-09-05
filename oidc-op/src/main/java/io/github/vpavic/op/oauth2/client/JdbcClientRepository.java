package io.github.vpavic.op.oauth2.client;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.minidev.json.JSONObject;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class JdbcClientRepository implements ClientRepository {

	private static final String INSERT_STATEMENT = "INSERT INTO clients(id, content) VALUES (?, ?)";

	private static final String SELECT_BY_ID_STATEMENT = "SELECT content FROM clients WHERE id = ?";

	private static final String SELECT_ALL_STATEMENT = "SELECT content FROM clients";

	private static final String UPDATE_STATEMENT = "UPDATE clients SET content = ? WHERE id = ?";

	private static final String DELETE_STATEMENT = "DELETE FROM clients WHERE id = ?";

	private static final ClientMapper clientMapper = new ClientMapper();

	private final JdbcOperations jdbcOperations;

	public JdbcClientRepository(JdbcOperations jdbcOperations) {
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional
	public void save(OIDCClientInformation client) {
		String id = client.getID().getValue();
		String content = client.toJSONObject().toString();

		int updatedCount = this.jdbcOperations.update(UPDATE_STATEMENT, ps -> {
			ps.setString(1, content);
			ps.setString(2, id);
		});

		if (updatedCount == 0) {
			this.jdbcOperations.update(INSERT_STATEMENT, ps -> {
				ps.setString(1, id);
				ps.setString(2, content);
			});
		}
	}

	@Override
	@Transactional(readOnly = true)
	public OIDCClientInformation findByClientId(ClientID clientID) {
		String id = clientID.getValue();

		try {
			return this.jdbcOperations.queryForObject(SELECT_BY_ID_STATEMENT, clientMapper, id);
		}
		catch (EmptyResultDataAccessException e) {
			return null;
		}
	}

	@Override
	@Transactional(readOnly = true)
	public List<OIDCClientInformation> findAll() {
		return this.jdbcOperations.query(SELECT_ALL_STATEMENT, clientMapper);
	}

	@Override
	@Transactional
	public void deleteByClientId(ClientID clientID) {
		String id = clientID.getValue();

		this.jdbcOperations.update(DELETE_STATEMENT, ps -> ps.setString(1, id));
	}

	private static class ClientMapper implements RowMapper<OIDCClientInformation> {

		@Override
		public OIDCClientInformation mapRow(ResultSet rs, int rowNum) throws SQLException {
			try {
				JSONObject jsonObject = JSONObjectUtils.parse(rs.getString(1));
				return OIDCClientInformation.parse(jsonObject);
			}
			catch (ParseException e) {
				throw new RuntimeException(e);
			}
		}

	}

}
