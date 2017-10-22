package io.github.vpavic.oauth2.userinfo;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public interface UserInfoMapper {

	UserInfo map(String principal, Scope scope);

}
