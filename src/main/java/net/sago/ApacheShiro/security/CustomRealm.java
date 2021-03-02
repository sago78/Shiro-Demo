package net.sago.ApacheShiro.security;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.sql.SQLException;
import java.util.*;

public class CustomRealm extends JdbcRealm {
    private  static final Logger logger = LogManager.getLogger(CustomRealm.class);
    private Map<String, String> credentials = new HashMap<>();
    private Map<String, Set> roles = new HashMap<>();
    private Map<String, Set> permissions = new HashMap<>();

    {
        credentials.put("Tom", "password");
        credentials.put("Jerry", "password");

        roles.put("Jerry", new HashSet<>(Arrays.asList("ADMIN")));
        roles.put("Tom", new HashSet<>(Arrays.asList("USER")));

        permissions.put("ADMIN", new HashSet<>(Arrays.asList("READ", "WRITE")));
        permissions.put("USER", new HashSet<>(Arrays.asList("READ")));
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken userToken = (UsernamePasswordToken) token;

        if (userToken.getUsername() == null || userToken.getUsername().isEmpty() ||
                !credentials.containsKey(userToken.getUsername())) {
            throw new UnknownAccountException("User doesn't exist");
        }
        return new SimpleAuthenticationInfo(userToken.getUsername(),credentials.get(userToken.getUsername()), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        Set roles = new HashSet<>();
        Set permissions = new HashSet<>();

        for (Object user : principals) {
            try {
                roles.addAll(getRoleNamesForUser(null, (String) user));
                permissions.addAll(getPermissions(null, null, roles));
            } catch (SQLException e) {
                logger.error(e.getMessage());
            }
        }
        SimpleAuthorizationInfo authInfo = new SimpleAuthorizationInfo(roles);
        authInfo.setStringPermissions(permissions);
        return authInfo;
    }
}
