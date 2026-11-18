package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest.TestProperties;
import org.bouncycastle.util.test.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SmartCardTestSuite
{
    public static List<Test> getGenericTestsFor(
            OpenPGPSmartCardManager m,
            TestProperties p)
    {
        return new ArrayList<>(Arrays.asList(
                new AnonymousRecipientSmartCardDecryptionTest(m, p),
                new OpenPGPSmartCardBackendTest(m, p),
                new ShortenedOpenPGPIdentifierForLegacyDevicesTest(m, p),
                new SmartCardChangePINTest(m, p),
                new SmartCardKeyGenerationTest(m, p),
                new SmartCardMessageDecryptionTest(m, p),
                new SmartCardMessageSigningTest(m, p),
                new SmartCardUserPinOwnershipTest(m, p),
                new SmartCardWithV6KeysTest(m, p),
                new UnrelatedSmartCardMessageDecryptionTest(m, p)
        ));
    }
}
