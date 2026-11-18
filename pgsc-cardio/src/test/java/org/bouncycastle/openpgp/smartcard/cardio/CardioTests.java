package org.bouncycastle.openpgp.smartcard.cardio;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestSuite;
import org.bouncycastle.openpgp.smartcard.test.SmartCardWithV6KeysTest;
import org.bouncycastle.openpgp.smartcard.test.UnrelatedSmartCardMessageDecryptionTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;

import java.security.Security;
import java.util.List;

public class CardioTests
        extends TestCase
{

    public CardioTests()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testOnBcCardioSmartCard()
    {
        AbstractOpenPGPSmartCardTest.TestProperties p;
        OpenPGPSmartCardManager m;
        try
        {
            p = CardioTestInstanceProvider.defaultProperties();
            m = new OpenPGPSmartCardManager();
            m.addBackend(CardioTestInstanceProvider.prepareBackend(p, new BcOpenPGPSmartCardImplementation()));
        }
        catch (CardioTestInstanceProvider.CardioSetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on BC Cardio: " + e.getMessage());
            return;
        }

        runWith(m, p);
    }

    public void testOnJcaJceCardioSmartCard()
    {
        AbstractOpenPGPSmartCardTest.TestProperties p;
        OpenPGPSmartCardManager m;
        try
        {
            p = CardioTestInstanceProvider.defaultProperties();
            m = new OpenPGPSmartCardManager();
            m.addBackend(CardioTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
        }
        catch (CardioTestInstanceProvider.CardioSetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on JCE Cardio: " + e.getMessage());
            return;
        }

        runWith(m, p);
    }

    private void runWith(OpenPGPSmartCardManager m, AbstractOpenPGPSmartCardTest.TestProperties p)
    {
        List<Test> tests = SmartCardTestSuite.getGenericTestsFor(m, p);
        tests.clear();
        tests.add(new SmartCardWithV6KeysTest(m, p));
        tests.add(new UnrelatedSmartCardMessageDecryptionTest(m, p));
        // Add additional cardio-related tests here

        for (int i = 0; i != tests.size(); i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests.get(i).perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    public static void main(String[] args)
    {
        new CardioTests().testOnBcCardioSmartCard();
    }
}
