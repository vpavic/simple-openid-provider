package io.github.vpavic.op.userinfo;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import org.springframework.stereotype.Component;

@Component
public class NullClaimsMapper implements ClaimsMapper {

	@Override
	public void map(ClaimsSet claims, Scope scope) {
	}

}
