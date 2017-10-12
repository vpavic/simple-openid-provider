package io.github.vpavic.rp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(properties = { "spring.security.oauth2.client.registration.simple-op-code.client-id=test-client",
		"spring.security.oauth2.client.registration.simple-op-code.client-secret=test-secret"})
public class RelyingPartyApplicationTests {

	@Test
	public void contextLoads() {
	}

}
