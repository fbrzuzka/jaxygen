/*
 * Copyright 2019 jakub knast <jakub.knast@xdsnet.pl>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jaxygen.invoker;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

/**
 *
 * @author jakub knast jakub.knast@xdsnet.pl
 */
public class XDASecurityUtils {

    public static Session getSession() {
        return SecurityUtils.getSubject().getSession();
    }

    public static Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    public static void login(AuthenticationToken authenticationToken) {
        getSubject().login(authenticationToken);
    }

    public static void logout() {
        getSubject().logout();
    }

    public static boolean isAuthenticated() {
        return getSubject().isAuthenticated();
    }

    public static Object getSessionAttribute(Object key) {
        return getSession().getAttribute(key);
    }

    public static void setSessionAttribute(Object key, Object value) {
        getSession().setAttribute(key, value);
    }

//    public static String getLoggedUserName() {
//        Object userNameAtrr = getSessionAttribute(Consts.USER_NAME_SEESION_ATTRIBUTE);
//        return userNameAtrr != null ? userNameAtrr.toString() : "";
//    }
//    public static void setLoggedUserName(String loggedUserName) {
//        setSessionAttribute(Consts.USER_NAME_SEESION_ATTRIBUTE, loggedUserName);
//    }
//    public static UsernamePasswordToken prepareLoginToken(String username, String password, DomainType domainType) {
//        UsernamePasswordToken loginToken;
//        if (domainType == DomainType.LDAP) {
//            loginToken = new LDAPToken(username, password);
//        } else if (domainType == DomainType.XDA) {
//            loginToken = new DatabaseToken(username, password);
//        } else if (domainType == DomainType.SUPERUSER) {
//            loginToken = new SuperuserToken(username, password);
//        } else {
//            throw new ServerInternalError("Unknown login method type: " + domainType.name());
//        }
//        loginToken.setRememberMe(false);
//        return loginToken;
//    }
}
