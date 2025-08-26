package icu.secnotes.config;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * 自定义Shiro Realm
 * 用于处理用户认证和权限
 */
public class CustomShiroRealm extends AuthorizingRealm {

    /**
     * 授权方法
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        
        // 根据用户名设置角色和权限
        if ("admin".equals(username)) {
            // admin用户拥有admin角色和所有权限
            authorizationInfo.addRole("admin");
            authorizationInfo.addRole("user");
            authorizationInfo.addStringPermission("user:view");
            authorizationInfo.addStringPermission("user:edit");
            authorizationInfo.addStringPermission("user:delete");
            authorizationInfo.addStringPermission("admin:view");
            authorizationInfo.addStringPermission("admin:edit");
            authorizationInfo.addStringPermission("admin:delete");
        } else if ("user".equals(username)) {
            // user用户拥有user角色和部分权限
            authorizationInfo.addRole("user");
            authorizationInfo.addStringPermission("user:view");
            authorizationInfo.addStringPermission("user:edit");
            // 注意：user角色没有user:delete权限，这样可以演示权限差异
        }
        
        return authorizationInfo;
    }

    /**
     * 认证方法
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        
        // 验证用户名和密码
        if ("admin".equals(username)) {
            return new SimpleAuthenticationInfo(username, "admin", getName());
        } else if ("user".equals(username)) {
            return new SimpleAuthenticationInfo(username, "user", getName());
        }
        
        throw new UnknownAccountException("用户不存在");
    }
} 