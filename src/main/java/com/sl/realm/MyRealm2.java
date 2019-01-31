package com.sl.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

public class MyRealm2 implements Realm {
    @Override
    public String getName() {
        return "myrealm2";
    }

    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        // 仅支持UsernamePasswordToken
        return authenticationToken instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 得到用户名
        String username = (String) authenticationToken.getPrincipal();
        // 得到密码
        String password = new String((char[]) authenticationToken.getCredentials());
        if (!"zhang".equals(username)) {
            // 如果用户名错误
            throw new UnknownAccountException();
        }
        if (!"123".equals(password)) {
            // 如果密码错误
            throw new IncorrectCredentialsException();
        }
        // 如果身份认证成功，返回一个AuthenticationInfo实现
        return new SimpleAuthenticationInfo(username, "zhang@163.com", getName());
    }
}
