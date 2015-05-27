package net.elfin.security;

import java.security.BasicPermission;
import java.security.Permission;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.PropertyPermission;

/**
 *
 * @author roskens
 */
public class NegatedPropertyPermission extends BasicPermission {
    private static final long serialVersionUID = 1L;
    private static final String ENABLE_ALL_READ = "<<ENABLE-ALL-READ>>";
    private static final String ENABLE_ALL_WRITE = "<<ENABLE-ALL-WRITE>>";
    
    private final List<String> names;
    private final List<String> actions;
    private final boolean enableGlobalWrite;
    private final boolean enableGlobalRead;
    
    public NegatedPropertyPermission(final String name, final String actions) {
        super(name);
        this.names = Arrays.asList(name.split("\\s*,\\s*"));
        Collections.sort(this.names);
        this.actions = Arrays.asList(actions.split("\\s*,\\s*"));
        Collections.sort(this.actions);
        
        enableGlobalWrite = this.names.contains(ENABLE_ALL_WRITE);
        enableGlobalRead = this.names.contains(ENABLE_ALL_READ);
    }
    
    public NegatedPropertyPermission(final String name) {
        this(name, "read,write");
    }
    
    @Override
    public String getActions() {
        return String.join(",", this.actions);
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("(");
        sb.append("\"");
        sb.append(this.getClass());
        sb.append("\"");
        
        sb.append(" \"");
        sb.append(getName());
        sb.append("\"");

        sb.append(" \"");
        sb.append(getActions());
        sb.append("\"");

        sb.append(")");
        
        return sb.toString();
    }
    
    @Override
    public boolean implies(Permission p) {
        if (p instanceof PropertyPermission) {
            System.err.println("implies check: " + this + " : " + p);
            if (this.names.contains(p.getName())) {
                System.err.println("names.contains('"+p.getName()+"')");
                if (this.containsActions(p.getActions())) {
                    System.err.println("actions.contains('"+p.getActions()+"')");
                    return false;
                }
            }
            System.err.println("p.getActions: " + p.getActions());
            System.err.println("enableGlobalRead: " + enableGlobalRead);
            System.err.println("enableGlobalWrite: " + enableGlobalWrite);
            if (p.getActions().contains("read") && p.getActions().contains("write") && !enableGlobalRead && !enableGlobalWrite) {
                System.err.println("implies: returning false (no global read/write)");
                return false;
            }
            if (p.getActions().contains("read") && !enableGlobalRead) {
                System.err.println("implies: returning false (global read/write)");
                return false;
            }
            if (p.getActions().contains("write") && !enableGlobalWrite) {
                System.err.println("implies: returning false (global read/write)");
                return false;
            }
            return true;
        }
        return false;
    }
    
    private boolean containsActions(final String actions) {
        for(String act : actions.split("\\s*,\\s*")) {
            if(this.actions.contains(act)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 97 * hash + Objects.hashCode(this.names) + Objects.hashCode(this.actions);
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
        final NegatedPropertyPermission other = (NegatedPropertyPermission) obj;
        if (!Objects.equals(this.names, other.names)) {
            return false;
        }
        if (!Objects.equals(this.actions, other.actions)) {
            return false;
        }
        return true;
    }
}
