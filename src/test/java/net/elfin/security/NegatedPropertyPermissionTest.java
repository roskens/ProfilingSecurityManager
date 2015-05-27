package net.elfin.security;

import java.util.PropertyPermission;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

/**
 *
 * @author roskens
 */
public class NegatedPropertyPermissionTest {
    NegatedPropertyPermission np = new NegatedPropertyPermission("*,javax.net.ssl.keyStorePassword,javax.net.ssl.trustStorePassword,<<ENABLE-ALL-READ>>");

    @Rule
    public TestName test = new TestName();
    
    @Before
    public void before() {
        System.out.println("-------- begin test " + test.getMethodName() + "--------");
    }
    
    @After
    public void after() {
        System.out.println("-------- end test " + test.getMethodName() + "--------\n");
    }
    
    @Test
    public void allowAllRead() {
        PropertyPermission p = new PropertyPermission("*", "read");
        Assert.assertFalse("Cannot read any property", np.implies(p));
    }

    @Test
    public void allowAllReadWrite() {
        PropertyPermission p = new PropertyPermission("*", "read,write");
        Assert.assertFalse("Cannot read,write any property", np.implies(p));
    }

    @Test
    public void allowAllWrite() {
        PropertyPermission p = new PropertyPermission("*", "write");
        Assert.assertFalse("Cannot write any property", np.implies(p));
    }

    @Test
    public void disallowKeyStorePassword() {
        PropertyPermission p = new PropertyPermission("javax.net.ssl.keyStorePassword", "read");
        Assert.assertFalse("Cannot read javax.net.ssl.keyStorePassword", np.implies(p));

        p = new PropertyPermission("javax.net.ssl.keyStorePassword", "write");
        Assert.assertFalse("Cannot write javax.net.ssl.keyStorePassword", np.implies(p));

        p = new PropertyPermission("javax.net.ssl.keyStorePassword", "read,write");
        Assert.assertFalse("Cannot read,write javax.net.ssl.keyStorePassword", np.implies(p));
    }

    @Test
    public void disallowTrustStorePassword() {
        PropertyPermission p = new PropertyPermission("javax.net.ssl.trustStorePassword", "read");
        Assert.assertFalse("Cannot read javax.net.ssl.trustStorePassword", np.implies(p));

        p = new PropertyPermission("javax.net.ssl.trustStorePassword", "write");
        Assert.assertFalse("Cannot write javax.net.ssl.trustStorePassword", np.implies(p));

        p = new PropertyPermission("javax.net.ssl.trustStorePassword", "read,write");
        Assert.assertFalse("Cannot read,write javax.net.ssl.trustStorePassword", np.implies(p));
    }

    @Test
    public void allowTmpDirRead() {
        PropertyPermission p = new PropertyPermission("java.io.tmpdir", "read");
        Assert.assertTrue("Cannot read java.io.tmpdir", np.implies(p));

        p = new PropertyPermission("java.io.tmpdir", "write");
        Assert.assertFalse("Cannot write java.io.tmpdir", np.implies(p));

        p = new PropertyPermission("java.io.tmpdir", "read,write");
        Assert.assertFalse("Can read,write java.io.tmpdir", np.implies(p));
    }
}
