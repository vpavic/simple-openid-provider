package io.github.vpavic.op.oauth2.client;

import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class JdbcClientRepository implements ClientRepository {

	private static final String INSERT_STATEMENT = "INSERT INTO clients(id, issue_date, metadata, secret, registration_uri, access_token) VALUES (?, ?, ?, ?, ?, ?)";

	private static final String SELECT_BY_ID_STATEMENT = "SELECT id, issue_date, metadata, secret, registration_uri, access_token FROM clients WHERE id = ?";

	private static final String SELECT_ALL_STATEMENT = "SELECT id, issue_date, metadata, secret, registration_uri, access_token FROM clients";

	private static final String UPDATE_STATEMENT = "UPDATE clients SET metadata = ?, secret = ?, access_token = ? WHERE id = ?";

	private static final String DELETE_STATEMENT = "DELETE FROM clients WHERE id = ?";

	private static final ClientMapper clientMapper = new ClientMapper();

	private final JdbcOperations jdbcOperations;

	public JdbcClientRepository(JdbcOperations jdbcOperations) {
		Objects.requireNonNull(jdbcOperations, "jdbcOperations must not be null");

		this.jdbcOperations = jdbcOperations;
	}

	@Override
	@Transactional
	public void save(OIDCClientInformation clientInformation) {
		ClientID id = clientInformation.getID();
		Date issueDate = clientInformation.getIDIssueDate();
		OIDCClientMetadata metadata = clientInformation.getOIDCMetadata();
		Secret secret = clientInformation.getSecret();
		URI registrationUri = clientInformation.getRegistrationURI();
		BearerAccessToken accessToken = clientInformation.getRegistrationAccessToken();

		int updatedCount = this.jdbcOperations.update(UPDATE_STATEMENT, ps -> {
			ps.setString(1, metadata.toJSONObject().toJSONString());
			ps.setString(2, (secret != null) ? secret.getValue() : null);
			ps.setString(3, (accessToken != null) ? accessToken.getValue() : null);
			ps.setString(4, id.getValue());
		});

		if (updatedCount == 0) {
			this.jdbcOperations.update(INSERT_STATEMENT, ps -> {
				ps.setString(1, id.getValue());
				ps.setTimestamp(2, Timestamp.from(issueDate.toInstant()));
				ps.setString(3, metadata.toJSONObject().toJSONString());
				ps.setString(4, (secret != null) ? secret.getValue() : null);
				ps.setString(5, registrationUri.toString());
				ps.setString(6, (accessToken != null) ? accessToken.getValue() : null);
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
				String id = rs.getString(1);
				Date issueDate = rs.getTimestamp(2);
				String metadata = rs.getString(3);
				String secret = rs.getString(4);
				String registrationUri = rs.getString(5);
				String accessToken = rs.getString(6);

				return new OIDCClientInformation(new ClientID(id), issueDate,
						OIDCClientMetadata.parse(JSONObjectUtils.parse(metadata)),
						(secret != null) ? new Secret(secret) : null, URI.create(registrationUri),
						(accessToken != null) ? new BearerAccessToken(accessToken) : null);
			}
			catch (ParseException e) {
				throw new RuntimeException(e);
			}
		}

	}

}
