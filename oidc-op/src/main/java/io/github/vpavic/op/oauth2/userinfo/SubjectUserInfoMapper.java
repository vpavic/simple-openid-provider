package io.github.vpavic.op.oauth2.userinfo;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.stereotype.Component;

@Component
public class SubjectUserInfoMapper implements UserInfoMapper {

	@Override
	public UserInfo map(String principal, Scope scope) {
		return new UserInfo(new Subject(principal));
	}

}
