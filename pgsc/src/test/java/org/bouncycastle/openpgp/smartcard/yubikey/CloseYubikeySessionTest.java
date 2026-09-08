package org.bouncycastle.openpgp.smartcard.yubikey;

import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;

import java.io.IOException;

public class CloseYubikeySessionTest
        extends AbstractOpenPGPSmartCardTest
{

    public CloseYubikeySessionTest(OpenPGPSmartCardManager manager, TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        if (!(card instanceof YubikeyOpenPGPSmartCard))
        {
            fail("Cannot run test with non-Yubikey");
        }

        YubikeyOpenPGPSmartCard yubikey = (YubikeyOpenPGPSmartCard) card;
        OpenPgpSession session;
        try
        {
            session = yubikey.openSession();
        }
        catch (ApduException e)
        {
            throw new CardException(e);
        }

        try
        {
            yubikey.openSession();
        }
        catch (IOException e)
        {
            isTrue(e.getMessage().contains("Exclusive access"));
        }
        catch (ApduException e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            session.close();
        }
    }

    @Override
    public String getName()
    {
        return "CloseYubikeySessionTest";
    }

    public static void main(String[] args)
    {
        OpenPGPSmartCardManager m;
        TestProperties p;

        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();

            // BCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new BcOpenPGPSmartCardImplementation()));
            runTest(new CloseYubikeySessionTest(m, p));

            // JCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
            runTest(new CloseYubikeySessionTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of CloseYubikeySessionTest on Yubikey: " + e.getMessage());
        }
    }
}
