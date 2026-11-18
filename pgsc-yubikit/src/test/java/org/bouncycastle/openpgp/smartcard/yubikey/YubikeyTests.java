package org.bouncycastle.openpgp.smartcard.yubikey;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest.TestProperties;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestSuite;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;

import java.util.List;

public class YubikeyTests
        extends TestCase
{
    private List<Test> getTests(OpenPGPSmartCardManager m,
                                TestProperties p)
    {
        List<Test> tests = SmartCardTestSuite.getGenericTestsFor(m, p);
        tests.add(new CloseYubikeySessionTest(m, p));
        return tests;
    }

    private void runWith(OpenPGPSmartCardManager m, TestProperties p)
    {
        List<Test> tests = getTests(m, p);

        for (int i = 0; i != tests.size(); i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests.get(i).perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    public void testOnBcYubikeySmartCard()
    {
        TestProperties p;
        OpenPGPSmartCardManager m;
        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();
            m = new OpenPGPSmartCardManager();
            m.addBackend(YubikeyTestInstanceProvider.prepareBackend(p, new BcOpenPGPSmartCardImplementation()));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on BC Yubikey: " + e.getMessage());
            return;
        }

        runWith(m, p);
    }

    public void testOnJcaJceYubikeySmartCard()
    {
        TestProperties p;
        OpenPGPSmartCardManager m;
        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();
            m = new OpenPGPSmartCardManager();
            m.addBackend(YubikeyTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on JCE Yubikey: " + e.getMessage());
            return;
        }

        runWith(m, p);
    }

    public static void main(String[] args) {
        YubikeyTests t = new YubikeyTests();
        t.testOnBcYubikeySmartCard();
    }
}
