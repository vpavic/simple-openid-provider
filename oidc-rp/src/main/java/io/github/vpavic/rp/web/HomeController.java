package io.github.vpavic.rp.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/")
public class HomeController {

	@GetMapping
	public Authentication home(Authentication authentication) {
		return authentication;
	}

}
