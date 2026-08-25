package org.bouncycastle.openpgp.smartcard.yubikey;


import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest.TestProperties;

import java.io.FileNotFoundException;
import java.util.Collections;
import java.util.List;

public class YubikeyTestInstanceProvider
{
    public static TestProperties defaultProperties()
            throws YubikeySetupException
    {
        try
        {
            TestProperties p = TestProperties.fromFile("yubikey.properties");
            return p;
        }
        catch (FileNotFoundException e)
        {
            throw new YubikeySetupException("Missing yubikey.properties file");
        }
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend()
            throws YubikeySetupException
    {
        return prepareBackend(YubikeyOpenPGPSmartCardBackend.bcImpl());
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            YubikeyOpenPGPSmartCardBackend.YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
            throws YubikeySetupException
    {
        TestProperties p = defaultProperties();
        return prepareBackend(p, decryptorFactoryProvider);
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            TestProperties properties,
            YubikeyOpenPGPSmartCardBackend.YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
    {
        return prepareBackend(Collections.singletonList(properties), decryptorFactoryProvider);
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            List<TestProperties> propertiesList,
            YubikeyOpenPGPSmartCardBackend.YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
    {
        YubikeyOpenPGPSmartCardBackend backend = YubikeyOpenPGPSmartCardBackend.createInstance(decryptorFactoryProvider);
        for (TestProperties properties : propertiesList)
        {
            backend.addAllowedCardSerial(properties.getSerialNumber());
        }
        return backend;
    }

    public static class YubikeySetupException extends Exception
    {
        public YubikeySetupException(String message)
        {
            super(message);
        }
    }
}
