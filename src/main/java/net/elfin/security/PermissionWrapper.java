/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.elfin.security;

import java.io.FilePermission;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.ReflectPermission;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.security.AllPermission;
import java.security.Permission;
import java.security.SecurityPermission;
import java.security.UnresolvedPermission;
import java.util.Objects;
import java.util.PropertyPermission;
import java.util.logging.LoggingPermission;
import javax.management.MBeanPermission;
import javax.management.MBeanServerPermission;
import javax.management.MBeanTrustPermission;
import javax.security.auth.AuthPermission;
import sun.security.provider.PolicyParser;
import sun.security.util.SecurityConstants;

/**
 *
 * @author roskens
 */
class PermissionWrapper {

    private Boolean m_found = Boolean.FALSE;
    private final String m_type;
    private final String m_name;
    private final String m_action;
    private Permission m_permission = null;
    private static final Class[] PARAMS0 = {};
    private static final Class[] PARAMS1 = {String.class};
    private static final Class[] PARAMS2 = {String.class, String.class};

    PermissionWrapper(PolicyParser.PermissionEntry pe) {
        this(pe.permission, pe.name, pe.action);
    }

    PermissionWrapper(String type, String name, String action) {
        m_type = type;
        m_name = name;
        m_action = action;

        m_permission = new UnresolvedPermission(
                type,
                name,
                action,
                null);
        try {
            m_permission = getInstance(type, name, action);
        } catch (ClassNotFoundException ex) {
            //System.err.println(ex);

        } catch (InstantiationException ex) {
            //System.err.println(ex);

        } catch (IllegalAccessException ex) {
            //System.err.println(ex);

        } catch (NoSuchMethodException ex) {
            //System.err.println(ex);

        } catch (InvocationTargetException ex) {
            //System.err.println(ex);

        } finally {

        }
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.m_type);
        hash = 53 * hash + Objects.hashCode(this.m_name);
        hash = 53 * hash + Objects.hashCode(this.m_action);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PermissionWrapper other = (PermissionWrapper) obj;
        if (!Objects.equals(this.m_type, other.m_type)) {
            return false;
        }
        if (!Objects.equals(this.m_name, other.m_name)) {
            return false;
        }
        if (!Objects.equals(this.m_action, other.m_action)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return asString(true);
    }

    public String asString(boolean showAll) {
        if (!showAll && m_found) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("   permission ").append(getType());
        if (getName() != null) {
            final String permissionName = getName();
            final String escapedPermissionName = permissionName.replace("\"", "\\\"").replace("\r", "\\\r");
            sb.append(" \"").append(escapedPermissionName).append("\"");
        }
        if (getActions() != null && !getActions().isEmpty()) {
            sb.append(", \"").append(getActions()).append("\"");
        }
        sb.append(";");
        //sb.append("// found=").append(m_found);
        sb.append("\n");

        return sb.toString();
    }

    /*
     * Copied from sun.security.provider.PolicyFile
     */
    private static final Permission getInstance(String type, String name, String actions)
            throws ClassNotFoundException,
            InstantiationException,
            IllegalAccessException,
            NoSuchMethodException,
            InvocationTargetException {
        //XXX we might want to keep a hash of created factories...
        Class<?> pc = Class.forName(type);
        Permission answer = getKnownInstance(pc, name, actions);
        if (answer != null) {
            return answer;
        }

        if (name == null && actions == null) {
            try {
                Constructor<?> c = pc.getConstructor(PARAMS0);
                return (Permission) c.newInstance(new Object[]{});
            } catch (NoSuchMethodException ne) {
                try {
                    Constructor<?> c = pc.getConstructor(PARAMS1);
                    return (Permission) c.newInstance(
                            new Object[]{name});
                } catch (NoSuchMethodException ne1) {
                    Constructor<?> c = pc.getConstructor(PARAMS2);
                    return (Permission) c.newInstance(
                            new Object[]{name, actions});
                }
            }
        } else {
            if (name != null && actions == null) {
                try {
                    Constructor<?> c = pc.getConstructor(PARAMS1);
                    return (Permission) c.newInstance(new Object[]{name});
                } catch (NoSuchMethodException ne) {
                    Constructor<?> c = pc.getConstructor(PARAMS2);
                    return (Permission) c.newInstance(
                            new Object[]{name, actions});
                }
            } else {
                Constructor<?> c = pc.getConstructor(PARAMS2);
                return (Permission) c.newInstance(
                        new Object[]{name, actions});
            }
        }
    }

    /*
     * Copied from sun.security.provider.PolicyFile
     * Moved some Permissions out from the commented out section.
     */
    private static final Permission getKnownInstance(Class claz, String name, String actions) {
        // XXX shorten list to most popular ones?
        if (claz.equals(FilePermission.class)) {
            return new FilePermission(name, actions);
        } else if (claz.equals(SocketPermission.class)) {
            return new SocketPermission(name, actions);
        } else if (claz.equals(RuntimePermission.class)) {
            return new RuntimePermission(name, actions);
        } else if (claz.equals(PropertyPermission.class)) {
            return new PropertyPermission(name, actions);
        } else if (claz.equals(NetPermission.class)) {
            return new NetPermission(name, actions);
        } else if (claz.equals(AllPermission.class)) {
            return SecurityConstants.ALL_PERMISSION;
        } else if (claz.equals(ReflectPermission.class)) {
            return new ReflectPermission(name, actions);
        } else if (claz.equals(LoggingPermission.class)) {
            return new LoggingPermission(name, actions);
        } else if (claz.equals(SecurityPermission.class)) {
            return new SecurityPermission(name, actions);
        } else if (claz.equals(MBeanPermission.class)) {
            return new MBeanPermission(name, actions);
        } else if (claz.equals(MBeanServerPermission.class)) {
            return new MBeanServerPermission(name, actions);
        } else if (claz.equals(MBeanTrustPermission.class)) {
            return new MBeanTrustPermission(name, actions);
        } else if (claz.equals(AuthPermission.class)) {
            return new AuthPermission(name, actions);
            /*
             } else if (claz.equals(PrivateCredentialPermission.class)) {
             return new PrivateCredentialPermission(name, actions);
             } else if (claz.equals(ServicePermission.class)) {
             return new ServicePermission(name, actions);
             } else if (claz.equals(DelegationPermission.class)) {
             return new DelegationPermission(name, actions);
             } else if (claz.equals(SerializablePermission.class)) {
             return new SerializablePermission(name, actions);
             } else if (claz.equals(AudioPermission.class)) {
             return new AudioPermission(name, actions);
             } else if (claz.equals(SSLPermission.class)) {
             return new SSLPermission(name, actions);
             } else if (claz.equals(SQLPermission.class)) {
             return new SQLPermission(name, actions);
             */
        } else {
            return null;
        }
    }

    public String getType() {
        return m_type;
    }

    public String getName() {
        return m_name;
    }

    public String getActions() {
        return m_action;
    }

    boolean implies(PermissionWrapper pw1) {
        if (m_permission == null) {
            return false;
        }
        if (pw1.m_permission == null) {
            return false;
        }

        return m_permission.implies(pw1.m_permission);
    }

    public Permission getPermission() {
        return m_permission;
    }

    public void setFound() {
        m_found = true;
    }

    boolean wasFound() {
        return m_found;
    }

}
