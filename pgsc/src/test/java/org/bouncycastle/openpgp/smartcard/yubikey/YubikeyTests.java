package org.bouncycastle.openpgp.smartcard.yubikey;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest.TestProperties;
import org.bouncycastle.openpgp.smartcard.test.AnonymousRecipientSmartCardDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageSigningTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardWithV6KeysTest;
import org.bouncycastle.openpgp.smartcard.test.UnrelatedSmartCardMessageDecryptionTest;
import org.bouncycastle.util.test.SimpleTestResult;

public class YubikeyTests
        extends TestCase
{

    public void testBCYK()
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

        AbstractOpenPGPSmartCardTest[] tests = new AbstractOpenPGPSmartCardTest[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new SmartCardMessageSigningTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new SmartCardWithV6KeysTest(m, p),
                        new CloseYubikeySessionTest(m, p),
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

    public void testJCEYK()
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

        AbstractOpenPGPSmartCardTest[] tests = new AbstractOpenPGPSmartCardTest[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new SmartCardWithV6KeysTest(m, p),
                        new CloseYubikeySessionTest(m, p),
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
}
