package io.github.vpavic.op.key;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/web/keys")
public class KeysWebController {

	private final KeyService keyService;

	private final ObjectWriter objectWriter;

	public KeysWebController(KeyService keyService, ObjectMapper objectMapper) {
		Objects.requireNonNull(keyService, "keyService must not be null");
		Objects.requireNonNull(objectMapper, "objectMapper must not be null");

		this.keyService = keyService;
		this.objectWriter = objectMapper.writer(SerializationFeature.INDENT_OUTPUT);
	}

	@GetMapping
	public String keys(Model model) throws JsonProcessingException {
		JWK activeKey = this.keyService.findActive();
		List<JWK> allKeys = this.keyService.findAll();

		JSONObject activeKeyJson = activeKey.toPublicJWK().toJSONObject();

		// @formatter:off
		Set<JSONObject> inactiveKeysJson = allKeys.stream()
				.filter(key -> !key.getKeyID().equals(activeKey.getKeyID()))
				.map(jwk -> jwk.toPublicJWK().toJSONObject())
				.collect(Collectors.toSet());
		// @formatter:on

		model.addAttribute("activeKey", this.objectWriter.writeValueAsString(activeKeyJson));
		model.addAttribute("inactiveKeys", this.objectWriter.writeValueAsString(inactiveKeysJson));

		return "keys";
	}

	@PostMapping(path = "/rotate")
	public String rotate() {
		this.keyService.rotate();

		return "redirect:/web/keys";
	}

}
