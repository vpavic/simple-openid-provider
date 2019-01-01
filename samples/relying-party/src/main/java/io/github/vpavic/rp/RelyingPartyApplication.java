package io.github.vpavic.rp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class RelyingPartyApplication {

	public static void main(String[] args) {
		SpringApplication.run(RelyingPartyApplication.class, args);
	}

	@GetMapping(path = "/")
	public Authentication home(Authentication authentication) {
		return authentication;
	}

}
