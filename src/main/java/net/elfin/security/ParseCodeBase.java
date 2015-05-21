package net.elfin.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author roskens
 */
public class ParseCodeBase {

    private static final Pattern GRANT_PATTERN = Pattern.compile("^grant\\s+(codeBase\\s*\\\"(.*?)\\\")?\\s*\\{(permission\\s+(.*?)\\s+\\\"(.*?)\\\"(, \\\"(.*?)\\\")?.*)\\}\\s*;\\s*$");
    private static final String CATALINA_HOME_DEFAULT = "/tomcat8/latest";
    private static final String CATALINA_BASE_DEFAULT = "/tomcat8/instance";

    public static void main(String args[]) throws FileNotFoundException, IOException {
        Map<String, String> subhash = new TreeMap<>();
        Set<String> grantList = new TreeSet<>();
        Set<String> codeBases = new TreeSet<>();
        Properties props = System.getProperties();
        addMapEntry(subhash, props, "java.home");
        addMapEntry(subhash, props, "catalina.home", CATALINA_HOME_DEFAULT);
        addMapEntry(subhash, props, "catalina.base", CATALINA_BASE_DEFAULT);
        addMapEntry(subhash, props, "applogdir", CATALINA_BASE_DEFAULT + File.separator + "logs");
        addMapEntry(subhash, props, "appdatadir", CATALINA_BASE_DEFAULT + File.separator + "data");
        addMapEntry(subhash, props, "appsecuredatadir", CATALINA_BASE_DEFAULT + File.separator + "securedata");
        addMapEntry(subhash, props, "apptmpdir", "/zdata/tomcat/apps/tmp");
        addMapEntry(subhash, props, "java.io.tmpdir");
        addMapEntry(subhash, props, "bi.dx.dir", "/dataexchange");

        //subhash.put(System.getenv("HOME"), "${user.home}");
        subhash.put(", \"\"", "");
        subhash.put("${file.separator}/", "${file.separator}");
        //subhash.put("\\", "\\\\");

        File f = new File(args[0]);
        // System.out.println("file[0]: "+f);
        try (BufferedReader rdr = new BufferedReader(new FileReader(f))) {
            while (rdr.ready()) {
                String line = rdr.readLine();
                Matcher m = GRANT_PATTERN.matcher(line);
                if (m.find()) {
                    //System.out.println(line);
                    grantList.add(line);
                    codeBases.add(m.group(2));
                }
            }
        }

        for (String codeBase : codeBases) {
            String cbGrant = "grant codeBase \"" + replaceAll(codeBase, subhash) + "\" {";
            System.out.println(cbGrant);
            for (String grant : grantList) {
                Matcher m = GRANT_PATTERN.matcher(grant);
                if (!m.find()) {
                    continue;
                }
                if (false) {
                System.out.println("m.group(0): " + m.group(0));
                System.out.println("m.group(1): " + m.group(1));
                System.out.println("m.group(2): " + m.group(2));
                System.out.println("m.group(3): " + m.group(3));
                System.out.println("m.group(4): " + m.group(4));
                System.out.println("m.group(5): " + m.group(5));
                System.out.println("m.group(6): " + m.group(6));
                }
                if (m.group(4).equals("java.util.PropertyPermission") && m.group(5).equals("*")) {
                    continue;
                }
                if (m.group(2).equals(codeBase)) {
                    System.out.print("    ");
                    System.out.println(replaceAll(m.group(3).trim(), subhash));
                }
            }
            System.out.println("};\n");
        }
    }

    private static String replaceAll(String input, Map<String, String> map) {
        String output = input.replaceAll("\\\\(?=[^\\\"\'])", "/");
        Set<String> keys = map.keySet();
        List<String> keyList = new ArrayList<>();
        keyList.addAll(keys);
        Collections.sort(keyList);
        for (String key : keyList) {
            output = output.replace(key, map.get(key));
        }
        output = output.replace("${file.separator}/", "${file.separator}");
        output = output.replace("${catalina.base}${file.separator}temp", "${java.io.tmpdir}");
        output = output.replace("${catalina.base}${file.separator}logs", "${applogdir}");
        return output;
    }

    private static void addMapEntry(Map<String, String> map, Properties props, final String propertyName) {
        addMapEntry(map, props, propertyName, null);
    }

    private static void addMapEntry(Map<String, String> map, Properties props, final String propertyName, final String defaultValue) {
        final String value = System.getProperty(propertyName, defaultValue);
        if (value != null) {
            final File file = new File(value);
            if (file.isDirectory()) {
                map.put(value, "${" + propertyName + "}${file.separator}");
                map.put(file.toURI().toString(), "file:${" + propertyName + "}${file.separator}");
            } else {
                map.put(value, "${" + propertyName + "}");
                map.put(file.toURI().toString(), "file:${" + propertyName + "}");
            }
        }
    }
}
