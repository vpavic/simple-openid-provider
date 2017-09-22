package io.github.vpavic.op.config;

import com.hazelcast.config.NetworkConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "hazelcast")
public class HazelcastProperties {

	private String groupName = "op";

	private String groupPassword = "op";

	private int port = NetworkConfig.DEFAULT_PORT;

	private String members;

	public String getGroupName() {
		return this.groupName;
	}

	public void setGroupName(String groupName) {
		this.groupName = groupName;
	}

	public String getGroupPassword() {
		return this.groupPassword;
	}

	public void setGroupPassword(String groupPassword) {
		this.groupPassword = groupPassword;
	}

	public int getPort() {
		return this.port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getMembers() {
		return this.members;
	}

	public void setMembers(String members) {
		this.members = members;
	}

}
