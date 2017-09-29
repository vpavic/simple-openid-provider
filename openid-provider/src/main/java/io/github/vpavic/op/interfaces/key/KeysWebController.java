package io.github.vpavic.op.interfaces.key;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.JWKSet;
import io.github.vpavic.op.oauth2.jwk.JwkSetService;
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

	private final JwkSetService jwkSetService;

	private final ObjectWriter objectWriter;

	public KeysWebController(JwkSetStore jwkSetStore, JwkSetService jwkSetService, ObjectMapper objectMapper) {
		Objects.requireNonNull(jwkSetStore, "jwkSetStore must not be null");
		Objects.requireNonNull(jwkSetService, "jwkSetService must not be null");
		Objects.requireNonNull(objectMapper, "objectMapper must not be null");

		this.jwkSetStore = jwkSetStore;
		this.jwkSetService = jwkSetService;
		this.objectWriter = objectMapper.writer(SerializationFeature.INDENT_OUTPUT);
	}

	@GetMapping
	public String keys(Model model) throws JsonProcessingException {
		JWKSet jwkSet = this.jwkSetStore.load();
		model.addAttribute("keys", this.objectWriter.writeValueAsString(jwkSet.toJSONObject()));

		return "keys";
	}

	@PostMapping(path = "/rotate")
	public String rotate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		this.jwkSetService.rotate();

		return "redirect:/web/keys";
	}

}
