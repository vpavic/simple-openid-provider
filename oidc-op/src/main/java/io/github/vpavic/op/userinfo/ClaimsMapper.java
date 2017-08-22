package io.github.vpavic.op.userinfo;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

public interface ClaimsMapper {

	void map(ClaimsSet claims, Scope scope);

}
