package org.bouncycastle.openpgp.smartcard.yubikey;


import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;
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
        return prepareBackend(new BcOpenPGPSmartCardImplementation());
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            OpenPGPSmartCardImplementation implementation)
            throws YubikeySetupException
    {
        TestProperties p = defaultProperties();
        return prepareBackend(p, implementation);
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            TestProperties properties,
            OpenPGPSmartCardImplementation implementation)
            throws YubikeySetupException
    {
        return prepareBackend(Collections.singletonList(properties), implementation);
    }

    public static YubikeyOpenPGPSmartCardBackend prepareBackend(
            List<TestProperties> propertiesList,
            OpenPGPSmartCardImplementation implementation)
            throws YubikeySetupException
    {
        YubikeyOpenPGPSmartCardBackend backend = YubikeyOpenPGPSmartCardBackend.createInstance(implementation);
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
