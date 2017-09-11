package io.github.vpavic.op.interfaces.client;

import java.util.List;
import java.util.Objects;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.op.oauth2.client.ClientRepository;

@Controller
@RequestMapping("/web/clients")
public class ClientsWebController {

	private final ClientRepository clientRepository;

	public ClientsWebController(ClientRepository clientRepository) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.clientRepository = clientRepository;
	}

	@GetMapping
	public String getClients(Model model) {
		List<OIDCClientInformation> clients = this.clientRepository.findAll();
		model.addAttribute("clients", clients);

		return "clients";
	}

}
