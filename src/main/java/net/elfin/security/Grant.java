/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.elfin.security;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.CodeSource;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import sun.net.www.ParseUtil;
import sun.security.provider.PolicyParser;

/**
 *
 * @author roskens
 */
public class Grant {

    private final CodeSource m_codeSource;
    private List<PermissionWrapper> m_permissions;
    private final String m_codeBase;

    public Grant(final String codeBase) {
        m_codeBase = codeBase;
        m_permissions = new ArrayList<>();
        m_codeSource = makeCodeSource();
    }

    public Grant(final String codeBase, final Enumeration<PolicyParser.PermissionEntry> permissionElements) {
        this(codeBase);
        addPermissions(permissionElements);
    }

    private CodeSource makeCodeSource() {
        try {
            Certificate[] certs = null;
            URL location = null;
            if (m_codeBase != null) {
                location = new URL(m_codeBase);
            }
            return canonicalizeCodebase(new CodeSource(location, certs));
        } catch (MalformedURLException e) {
        }
        return null;
    }

    @Override
    public String toString() {
        return asString(true);
    }

    public String asString(boolean showAll) {
        StringBuilder sb = new StringBuilder();
        if (!showAll) {
            if (!haveUnfoundPermissions()) {
                return sb.toString();
            }
        }
        sb.append("grant");
        if (m_codeBase != null) {
            sb.append(" codeBase \"").append(m_codeBase).append("\"");
        }
        sb.append(" {\n");
        for (PermissionWrapper p : m_permissions) {
            if (showAll || !p.wasFound()) {
                sb.append(p.asString(showAll));
            }
        }

        sb.append("}\n");
        return sb.toString();
    }

    public void addPermissions(Enumeration<PolicyParser.PermissionEntry> permissionElements) {
        while (permissionElements.hasMoreElements()) {
            PolicyParser.PermissionEntry pe = permissionElements.nextElement();
            m_permissions.add(new PermissionWrapper(pe));
        }
    }

    boolean compareCodeBase(Grant g1) {
        return compareCodeBase(g1.m_codeSource);
    }

    boolean compareCodeBase(CodeSource cs) {
        return m_codeSource.implies(cs);
    }

    String codeBase() {
        return m_codeSource.getLocation() != null ? m_codeSource.getLocation().toString() : null;
    }

    List<PermissionWrapper> getPermissions() {
        return m_permissions;
    }

    private boolean haveUnfoundPermissions() {
        boolean haveUnfound = false;
        for (PermissionWrapper p : m_permissions) {
            if (!p.wasFound()) {
                haveUnfound = true;
                break;
            }
        }
        return haveUnfound;
    }

    private static CodeSource canonicalizeCodebase(CodeSource cs) {

        String path = null;

        CodeSource canonCs = cs;
        URL u = cs.getLocation();
        if (u != null) {
            if (u.getProtocol().equals("jar")) {
                // unwrap url embedded inside jar url
                String spec = u.getFile();
                int separator = spec.indexOf("!/");
                if (separator != -1) {
                    try {
                        u = new URL(spec.substring(0, separator));
                    } catch (MalformedURLException e) {
                        // Fail silently. In this case, url stays what
                        // it was above
                    }
                }
            }
            if (u.getProtocol().equals("file")) {
                boolean isLocalFile = false;
                String host = u.getHost();
                isLocalFile = (host == null || host.equals("")
                        || host.equals("~") || host.equalsIgnoreCase("localhost"));

                if (isLocalFile) {
                    path = u.getFile().replace('/', File.separatorChar);
                    path = ParseUtil.decode(path);
                }
            }
        }

        if (path != null) {
            try {
                URL csUrl = null;
                path = canonPath(path);
                csUrl = ParseUtil.fileToEncodedURL(new File(path));

                canonCs = new CodeSource(csUrl, cs.getCertificates());
            } catch (IOException ioe) {
            }
        }
        return canonCs;
    }

    // Wrapper to return a canonical path that avoids calling getCanonicalPath()
    // with paths that are intended to match all entries in the directory
    private static String canonPath(String path) throws IOException {
        if (path.endsWith("*")) {
            path = path.substring(0, path.length() - 1) + "-";
            path = new File(path).getCanonicalPath();
            return path.substring(0, path.length() - 1) + "*";
        } else {
            return new File(path).getCanonicalPath();
        }
    }

    boolean addPermission(PermissionWrapper pw) {
        if (!m_permissions.contains(pw)) {
            return m_permissions.add(new PermissionWrapper(pw.getType(), pw.getName(), pw.getActions()));
        }
        return false;
    }

}
