package io.github.vpavic.op.interfaces.key;

import java.util.Objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.op.oauth2.jwk.JwkSetStore;

@Controller
@RequestMapping("/web/keys")
public class KeysWebController {

	private final JwkSetStore jwkSetStore;

	public KeysWebController(JwkSetStore jwkSetStore) {
		Objects.requireNonNull(jwkSetStore, "jwkSetStore must not be null");

		this.jwkSetStore = jwkSetStore;
	}

	@GetMapping
	public String keys(Model model) throws JsonProcessingException {
		JWKSet jwkSet = this.jwkSetStore.load();
		model.addAttribute("keys", jwkSet.toPublicJWKSet().getKeys());

		return "keys";
	}

	@PostMapping(path = "/rotate")
	public String rotate() {
		this.jwkSetStore.rotate();

		return "redirect:/web/keys";
	}

}
