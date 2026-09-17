package org.bouncycastle.openpgp.smartcard.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.smartcard.operator.PublicKeyConverterTest;
import org.bouncycastle.openpgp.smartcard.simulator.ShortenedOpenPGPIdentifierForLegacyDevicesTest;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorTests;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTests;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.test.SimpleTestResult;

import java.security.Security;

public class AllTests
        extends TestCase
{

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public void testUnits()
    {
        org.bouncycastle.util.test.Test[] tests = new org.bouncycastle.util.test.Test[]
                {
                        new ShortenedOpenPGPIdentifierForLegacyDevicesTest(),
                        new PublicKeyConverterTest(),
                        new MultiBackendTest(),
                        new FailingBackendTest()
                };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenPGP SmartCard Tests");

        suite.addTestSuite(SimulatorTests.class);
        suite.addTestSuite(YubikeyTests.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
            extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
