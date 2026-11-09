package org.bouncycastle.openpgp.smartcard.cardio;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest.TestProperties;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class CardioTestInstanceProvider
{
    public static TestProperties defaultProperties()
            throws CardioSetupException
    {
        try
        {
            TestProperties p = TestProperties.fromFile("cardio.properties");
            return p;
        }
        catch (FileNotFoundException e)
        {
            throw new CardioSetupException("Missing cardio.properties file");
        }
    }

    public static CardioOpenPGPSmartCardBackend prepareBackend()
            throws CardioSetupException
    {
        return prepareBackend(new BcOpenPGPSmartCardImplementation());
    }

    public static CardioOpenPGPSmartCardBackend prepareBackend(
            OpenPGPSmartCardImplementation implementation)
            throws CardioSetupException
    {
        TestProperties p = defaultProperties();
        return prepareBackend(p, implementation);
    }

    public static CardioOpenPGPSmartCardBackend prepareBackend(
            TestProperties properties,
            OpenPGPSmartCardImplementation implementation)
            throws CardioSetupException
    {
        return prepareBackend(Collections.singletonList(properties), implementation);
    }

    public static CardioOpenPGPSmartCardBackend prepareBackend(
            List<TestProperties> propertiesList,
            OpenPGPSmartCardImplementation implementation)
            throws CardioSetupException
    {
        CardioOpenPGPSmartCardBackend backend = new CardioOpenPGPSmartCardBackend(
                implementation,
                new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()));
        try
        {
            if (backend.listSmartCards().isEmpty())
            {
                throw new CardException("No devices found.");
            }
        }
        catch (CardException e)
        {
            throw new CardioSetupException("No devices plugged in.");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return backend;
    }

    public static class CardioSetupException extends Exception
    {
        public CardioSetupException(String message)
        {
            super(message);
        }
    }
}
