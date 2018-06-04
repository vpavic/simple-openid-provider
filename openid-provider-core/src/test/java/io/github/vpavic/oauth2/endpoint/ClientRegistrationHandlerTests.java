package io.github.vpavic.oauth2.endpoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientService;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link ClientRegistrationHandler}.
 */
class ClientRegistrationHandlerTests {

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private ClientService clientService = mock(ClientService.class);

	private ClientRegistrationHandler clientRegistrationHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
	}

	@Test
	void construct_NullClientRepository_ShouldThrowException() {
		assertThatThrownBy(() -> new ClientRegistrationHandler(null, this.clientService))
				.isInstanceOf(NullPointerException.class).hasMessage("clientRepository must not be null");
	}

	@Test
	void construct_NullClientService_ShouldThrowException() {
		assertThatThrownBy(() -> new ClientRegistrationHandler(this.clientRepository, null))
				.isInstanceOf(NullPointerException.class).hasMessage("clientService must not be null");
	}

	// TODO add more tests

}
