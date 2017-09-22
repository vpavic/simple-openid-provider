package io.github.vpavic.op.config;

import javax.sql.DataSource;

import org.springframework.cloud.config.java.AbstractCloudConfig;
import org.springframework.cloud.service.PooledServiceConnectorConfig;
import org.springframework.cloud.service.PooledServiceConnectorConfig.PoolConfig;
import org.springframework.cloud.service.relational.DataSourceConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;

@Configuration
@Profile("cloud")
public class CloudConfiguration extends AbstractCloudConfig {

	@Bean
	public DataSource dataSource() {
		PoolConfig poolConfig = new PoolConfig(4, 4, 3000);
		DataSourceConfig dataSourceConfig = new DataSourceConfig(poolConfig, null);
		return connectionFactory().dataSource(dataSourceConfig);
	}

	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		PoolConfig poolConfig = new PoolConfig(5, 30, 3000);
		PooledServiceConnectorConfig redisConnectionFactoryConfig = new PooledServiceConnectorConfig(poolConfig);
		return connectionFactory().redisConnectionFactory(redisConnectionFactoryConfig);
	}

}
