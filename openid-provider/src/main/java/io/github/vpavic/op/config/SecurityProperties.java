package io.github.vpavic.op.config;

import java.util.UUID;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("security")
public class SecurityProperties {

	private final User user = new User();

	public User getUser() {
		return this.user;
	}

	public static class User {

		private String name = "user";

		private String password = UUID.randomUUID().toString().replace("-", "").substring(16);

		private boolean defaultPassword = true;

		public String getName() {
			return this.name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getPassword() {
			return this.password;
		}

		public void setPassword(String password) {
			this.defaultPassword = false;
			this.password = password;
		}

		public boolean isDefaultPassword() {
			return this.defaultPassword;
		}

	}

}
