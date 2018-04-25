package io.github.vpavic.rp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(properties = { "spring.security.oauth2.client.registration.simple-op-code.client-id=test-client",
		"spring.security.oauth2.client.registration.simple-op-code.client-secret=test-secret"})
class RelyingPartyApplicationTests {

	@Test
	void contextLoads() {
	}

}
