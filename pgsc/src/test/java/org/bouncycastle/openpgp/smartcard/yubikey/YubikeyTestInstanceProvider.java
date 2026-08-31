package org.bouncycastle.openpgp.smartcard.yubikey;


import org.bouncycastle.openpgp.smartcard.card.CardException;
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
            throws YubikeySetupException
    {
        return prepareBackend(Collections.singletonList(properties), decryptorFactoryProvider);
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            List<TestProperties> propertiesList,
            YubikeyOpenPGPSmartCardBackend.YubikeyDecryptorFactoryProvider decryptorFactoryProvider)
            throws YubikeySetupException
    {
        YubikeyOpenPGPSmartCardBackend backend = YubikeyOpenPGPSmartCardBackend.createInstance(decryptorFactoryProvider);
        for (TestProperties properties : propertiesList)
        {
            backend.addAllowedCardSerial(properties.getSerialNumber());
        }
        try
        {
            if (backend.listSmartCards().isEmpty())
            {
                throw new CardException("No devices found.");
            }
        }
        catch (CardException e)
        {
            throw new YubikeySetupException("No devices plugged in.");
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
