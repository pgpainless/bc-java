package org.bouncycastle.openpgp.smartcard.cardio;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.AnonymousRecipientSmartCardDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.OpenPGPSmartCardBackendTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardChangePINTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardKeyGenerationTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageSigningTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardWithV6KeysTest;
import org.bouncycastle.openpgp.smartcard.test.UnrelatedSmartCardMessageDecryptionTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;

import java.security.Security;

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

        Test[] tests = getTests(m, p);

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
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

        Test[] tests = getTests(m, p);

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    private Test[] getTests(OpenPGPSmartCardManager m, AbstractOpenPGPSmartCardTest.TestProperties p)
    {
        Test[] tests = new Test[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new SmartCardMessageSigningTest(m, p),
                        new SmartCardKeyGenerationTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new SmartCardWithV6KeysTest(m, p),
                        new OpenPGPSmartCardBackendTest(m, p),
                        new SmartCardChangePINTest(m, p)
                };
        return tests;
    }

    public static void main(String[] args)
    {
        new CardioTests().testOnBcCardioSmartCard();
    }
}
