package com.sl;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.Test;

public class LoginLogoutTest {

    @Test
    public void testHelloworld() {
        // 1.获取SecurityManager工厂，此处使用ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-authenticator-all-success.ini");
        // 2.得到SecurityManager实例，并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        // 3.得到Subject及创建用户名/密码身份验证Token(即用户身份/凭证)
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        try {
            /**
             * 对于页面的错误消息展示，最好使用”用户名密码错误“，而不是”用户名错误/密码错误“，防止恶意用户非法扫描账号库
             */
            // 4.登录，即身份验证
            subject.login(token);
            printer("登录成功");
        } catch (LockedAccountException lae) {
            printer("锁定的账号", lae);
        } catch (UnknownAccountException uae) {
            printer("错误的账号", uae);
        } catch (ExcessiveAttemptsException eae) {
            printer("登录失败次数过多", eae);
        } catch (IncorrectCredentialsException ice) {
            printer("错误的凭证", ice);
        } catch (ExpiredCredentialsException ece) {
            printer("过期的凭证", ece);
        } catch (DisabledAccountException dae) {
            printer("禁用的账号", dae);
        } catch (AuthenticationException ae) {
            printer("身份验证失败", ae);
        }
        // 6.断言用户已经登录
        Assert.assertEquals(true, subject.isAuthenticated());
        // 7.退出
        subject.logout();
        printer("退出");
    }

    public void printer(String message, Object... object) {
        System.out.println(message + (0 == object.length ? "" : "：" + object[0].toString()));
    }
}