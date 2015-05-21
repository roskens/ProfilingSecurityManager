/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.elfin.security;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import sun.security.provider.PolicyParser;
import sun.security.provider.PolicyParser.PermissionEntry;

/**
 *
 * @author roskens
 */
public class Policy {

    private final List<Grant> m_grants;

    public Policy() {
        m_grants = new ArrayList<>();
    }

    @Override
    public String toString() {
        return asString(true);
    }

    public String asString(boolean showAll) {
        StringBuilder sb = new StringBuilder();
        for (Grant g : m_grants) {
            sb.append(g.asString(showAll));
        }
        return sb.toString();
    }

    void addGrant(PolicyParser.GrantEntry ge) {
        addGrant(ge.codeBase, ge.permissionElements());
    }

    void addGrant(final String codeBase, Enumeration<PermissionEntry> permissions) {
        m_grants.add(new Grant(codeBase, permissions));
    }

    List<Grant> getGrants() {
        return m_grants;
    }

    boolean addPermission(Grant g1, PermissionWrapper pw1) {
        for (Grant grant : m_grants) {
            if (grant.compareCodeBase(g1)) {
                if (grant.addPermission(pw1)) {
                    return true;
                }
            }
        }
        return false;
    }

    void reducePermissions() {
        Grant nullGrant = null;
        for (Grant grant : m_grants) {
            for (PermissionWrapper pw : grant.getPermissions()) {
                for (PermissionWrapper pw1 : grant.getPermissions()) {
                    if (!pw.equals(pw1)) {
                        if (pw.implies(pw1)) {
                            pw1.setFound();
                        }
                    }
                }
            }
            if (grant.codeBase() == null || grant.codeBase().isEmpty()) {
                nullGrant = grant;
            }
        }
        if (nullGrant != null) {
            for (Grant grant : m_grants) {
                if (grant.codeBase() == null) {
                    continue;
                }

                for (PermissionWrapper pw0 : nullGrant.getPermissions()) {
                    for (PermissionWrapper pw1 : grant.getPermissions()) {
                        if (pw0.equals(pw1) || pw0.implies(pw1)) {
                            pw1.setFound();
                        }
                    }
                }
            }
        }

    }

}
