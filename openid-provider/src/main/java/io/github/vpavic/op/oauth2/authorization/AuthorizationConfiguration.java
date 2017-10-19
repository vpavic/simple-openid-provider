package io.github.vpavic.op.oauth2.authorization;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.oauth2.client.ClientRepository;
import io.github.vpavic.op.oauth2.token.AccessTokenClaimsMapper;
import io.github.vpavic.op.oauth2.token.AuthorizationCodeService;
import io.github.vpavic.op.oauth2.token.IdTokenClaimsMapper;
import io.github.vpavic.op.oauth2.token.TokenService;
import io.github.vpavic.op.oauth2.userinfo.UserInfoMapper;

@Configuration
public class AuthorizationConfiguration {

	private final OIDCProviderMetadata providerMetadata;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final UserInfoMapper userInfoMapper;

	public AuthorizationConfiguration(OIDCProviderMetadata providerMetadata,
			ObjectProvider<ClientRepository> clientRepository,
			ObjectProvider<AuthorizationCodeService> authorizationCodeService,
			ObjectProvider<TokenService> tokenService, ObjectProvider<AccessTokenClaimsMapper> accessTokenClaimsMapper,
			ObjectProvider<IdTokenClaimsMapper> idTokenClaimsMapper, ObjectProvider<UserInfoMapper> userInfoMapper) {
		this.providerMetadata = providerMetadata;
		this.clientRepository = clientRepository.getObject();
		this.authorizationCodeService = authorizationCodeService.getObject();
		this.tokenService = tokenService.getObject();
		this.accessTokenClaimsMapper = accessTokenClaimsMapper.getObject();
		this.idTokenClaimsMapper = idTokenClaimsMapper.getObject();
		this.userInfoMapper = userInfoMapper.getObject();
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() {
		return new AuthorizationEndpoint(this.providerMetadata, this.clientRepository, this.authorizationCodeService,
				this.tokenService, this.accessTokenClaimsMapper, this.idTokenClaimsMapper, this.userInfoMapper);
	}

}
