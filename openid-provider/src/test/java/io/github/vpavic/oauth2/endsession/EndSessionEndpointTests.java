package io.github.vpavic.oauth2.endsession;

import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.thymeleaf.spring5.SpringTemplateEngine;
import org.thymeleaf.spring5.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring5.view.ThymeleafViewResolver;

import io.github.vpavic.oauth2.OpenIdProviderWebMvcConfiguration;
import io.github.vpavic.oauth2.client.ClientRepository;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link EndSessionEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration
public class EndSessionEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Before
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
	}

	@Test
	public void getEndSessionEndpoint() throws Exception {
		this.mvc.perform(get(EndSessionEndpoint.PATH_MAPPING)).andExpect(status().isOk())
				.andExpect(content().string(containsString("<title>Sign out</title>")));
	}

	@Configuration
	@EnableWebMvc
	@Import(OpenIdProviderWebMvcConfiguration.class)
	static class Config {

		@Bean
		public SpringResourceTemplateResolver templateResolver() {
			SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
			templateResolver.setPrefix("classpath:/templates/");
			templateResolver.setSuffix(".html");
			return templateResolver;
		}

		@Bean
		public SpringTemplateEngine templateEngine() {
			SpringTemplateEngine templateEngine = new SpringTemplateEngine();
			templateEngine.setTemplateResolver(templateResolver());
			return templateEngine;
		}

		@Bean
		public ViewResolver viewResolver() {
			ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
			viewResolver.setTemplateEngine(templateEngine());
			return viewResolver;
		}

		@Bean
		public ClientRepository clientRepository() {
			return mock(ClientRepository.class);
		}

		@Bean
		public EndSessionEndpoint endSessionEndpoint() {
			return new EndSessionEndpoint(new Issuer("http://example.com"), clientRepository());
		}

	}

}
