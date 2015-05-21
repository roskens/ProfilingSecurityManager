/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.elfin.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.TreeMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import sun.security.provider.PolicyParser;

/**
 *
 * @author roskens
 */
public class PolicyFileDiff {

    private static final Map<String, String> map = new TreeMap<>();
    private static final boolean debug = true;

    private static final String CATALINA_HOME_DEFAULT = "/tomcat8/latest";
    private static final String CATALINA_BASE_DEFAULT = "/tomcat8/instance";

    public static void main(String arg[]) throws Exception {
        addMapEntry("java.home");
        addMapEntry("catalina.home", CATALINA_HOME_DEFAULT);
        addMapEntry("catalina.base", CATALINA_BASE_DEFAULT);
        addMapEntry("applogdir", CATALINA_BASE_DEFAULT + File.separator + "logs");
        addMapEntry("appdatadir", CATALINA_BASE_DEFAULT + File.separator + "data");
        addMapEntry("java.io.tmpdir", CATALINA_BASE_DEFAULT + File.separator + "temp");
        addMapEntry("cybersourcedir", "/tomcat8/cybersource");
        addMapEntry("bi.dx.dir", "/dataexchange");
        map.put("${catalina.base}/logs", "${applogdir}");
        map.put("${catalina.base}/data", "${appdatadir}");
        map.put("/bi.env.eng/", "${bi.env}");

        if (System.getProperty("catalina.home") == null) {
            System.setProperty("catalina.home", CATALINA_HOME_DEFAULT);
        }
        if (System.getProperty("catalina.base") == null) {
            System.setProperty("catalina.base", CATALINA_BASE_DEFAULT);
        }
        if (System.getProperty("applogdir") == null) {
            System.setProperty("applogdir", CATALINA_BASE_DEFAULT + File.separator + "logs");
        }
        if (System.getProperty("appdatadir") == null) {
            System.setProperty("appdatadir", CATALINA_BASE_DEFAULT + File.separator + "data");
        }
        if (System.getProperty("appsecuredatadir") == null) {
            System.setProperty("appsecuredatadir", CATALINA_BASE_DEFAULT + File.separator + "securedata");
        }
        if (System.getProperty("apptmpdir") == null) {
            System.setProperty("apptmpdir", "/tomcat8/tmp");
        }
        System.setProperty("cybersourcedir", "/tomcat8/cybersource");
        System.setProperty("bi.dx.dir", "/dataexchange");
        System.setProperty("bi.env", "bi.env.eng");

        if (arg.length != 2) {
            displayUsage(1);
        }

        System.out.println("==== file 0 ====");
        File f0 = new File(arg[0]);
        if (!f0.exists()) {
            System.err.println("ERROR: File " + f0 + " is missing!");
            System.exit(1);
        }

        System.out.println("==== file 1 ====");
        File f1 = new File(arg[1]);
        if (!f1.exists()) {
            System.err.println("ERROR: File " + f1 + " is missing!");
            System.exit(1);
        }

        System.out.println("==== policy 0 ====");
        Policy p0 = readPolicyFile(f0);

        System.out.println("==== policy 1 ====");
        Policy p1 = readPolicyFile(f1);

        System.out.println("==== empty webapp policy ====");
        Policy webappPolicy = emptyWebAppPolicy();

        System.out.println("==== before compare ====");
        comparePolicies(p0, p1, webappPolicy);

        System.out.println("==== unused p0 policy ====");
        displayPolicy(p0, false);

        System.out.println("==== diff webapp policy ====");
        displayPolicy(webappPolicy, false);
    }

    private static String replaceByMap(String input) {
        String output = input;
        Set<String> keys = map.keySet();
        List<String> keyList = new ArrayList<>();
        keyList.addAll(keys);
        Collections.sort(keyList, new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                return Integer.compare(o2.length(), o1.length());
            }
        });
        for (String key : keyList) {
            String value = map.get(key);
            //System.out.println("map['"+key+"'] => '"+value+"'");
            if (output.contains(key)) {
                output = output.replace(key, value);
            }
        }
        return output;
    }

    private static Policy readPolicyFile(final File file) {
        Policy policy = new Policy();
        try (BufferedReader rdr = Files.newBufferedReader(file.toPath(), Charset.defaultCharset())) {
            PolicyParser parser = new PolicyParser(true);
            parser.read(rdr);
            Enumeration<PolicyParser.GrantEntry> enum_ = parser.grantElements();
            while (enum_.hasMoreElements()) {
                PolicyParser.GrantEntry ge = enum_.nextElement();
                policy.addGrant(ge);
            }
        } catch (PolicyParser.ParsingException e) {
            System.err.println("Error parsing file " + file + ": " + e);
        } catch (IOException e) {
            System.err.println("IO Error for file " + file + ": " + e);
        }
        return policy;
    }

    private static void comparePolicies(Policy p0, Policy p1, Policy diffPolicy) {
        for (Grant g0 : p0.getGrants()) {
            for (Grant g1 : p1.getGrants()) {
                comparePermissions(g0, g1);
            }
        }
        for (Grant g1 : p1.getGrants()) {
            for (PermissionWrapper pw1 : g1.getPermissions()) {
                if (!pw1.wasFound()) {
                    if (!pw1.getPermission().getName().equals("*"))
                        diffPolicy.addPermission(g1, pw1);
                }
            }
        }
        diffPolicy.reducePermissions();
    }

    private static void displayPolicy(Policy policy) {
        displayPolicy(policy, true);
    }

    private static void displayPolicy(Policy policy, boolean showAll) {
        if (debug) {
            System.out.println("----------------------------------------------------------------------");
            System.out.println(replaceByMap(policy.asString(showAll)));
            System.out.println("----------------------------------------------------------------------\n");
        }
    }

    private static void comparePermissions(Grant g0, Grant g1) {
        if (!g0.compareCodeBase(g1)) {
            return;
        }

        for (PermissionWrapper pw0 : g0.getPermissions()) {
            for (PermissionWrapper pw1 : g1.getPermissions()) {
                if (pw0.implies(pw1)) {
                    pw0.setFound();
                    pw1.setFound();
                }
            }
        }
    }

    private static Policy emptyWebAppPolicy() {
        Policy policy = new Policy();
        List<PolicyParser.PermissionEntry> perms = new ArrayList<>();
        String catalinaHome = System.getProperty("catalina.home", CATALINA_HOME_DEFAULT);
        String catalinaBase = System.getProperty("catalina.base", CATALINA_BASE_DEFAULT);

        policy.addGrant("file:" + catalinaHome + File.separator + "webapps" + File.separator + "ctech-management" + File.separator + "-", Collections.enumeration(perms));
        policy.addGrant("file:" + catalinaHome + File.separator + "webapps" + File.separator + "manager" + File.separator + "-", Collections.enumeration(perms));
        policy.addGrant("file:" + catalinaBase + File.separator + "webapps" + File.separator + "manager" + File.separator + "-", Collections.enumeration(perms));
        policy.addGrant("file:" + catalinaHome + File.separator + "webapps" + File.separator + "-", Collections.enumeration(perms));
        policy.addGrant("file:" + catalinaBase + File.separator + "webapps" + File.separator + "-", Collections.enumeration(perms));
        policy.addGrant(null, Collections.enumeration(perms));
        return policy;
    }

    private static void displayUsage(int exitCode) {
        System.out.println("Usage: PolicyFileDiff <policy-file> <policy-file>");
        System.exit(exitCode);
    }

    private static void addMapEntry(final String propertyName) {
        addMapEntry(propertyName, null);
    }

    private static void addMapEntry(final String propertyName, final String defaultValue) {
        final String value = System.getProperty(propertyName, defaultValue);
        if (value != null) {
            final File file = new File(value);
            if (file.isDirectory()) {
                if (value.endsWith(File.separator)) {
                    map.put(value, "${" + propertyName + "}${file.separator}");
                    if (File.separatorChar != '/') {
                        map.put(value.replace(File.separator, "/"), "${" + propertyName + "}${file.separator}");
                    }
                    map.put(file.toURI().toString(), "file:${" + propertyName + "}${file.separator}");
                } else {
                    map.put(value + File.separator, "${" + propertyName + "}${file.separator}");
                    if (File.separatorChar != '/') {
                        map.put(value.replace('\\', '/') + '/', "${" + propertyName + "}${file.separator}");
                    }
                    map.put(file.toURI().toString(), "file:${" + propertyName + "}${file.separator}");
                }
            } else {
                map.put(value, "${" + propertyName + "}");
                if (File.separatorChar != '/') {
                    map.put(value.replace('\\', '/'), "${" + propertyName + "}");
                }
                map.put(file.toURI().toString(), "file:${" + propertyName + "}");
            }
        }
    }

}
