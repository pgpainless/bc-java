package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;

import java.io.IOException;
import java.util.List;

public class SmartCardChangePINTest
        extends AbstractOpenPGPSmartCardTest
{

    public SmartCardChangePINTest(OpenPGPSmartCardManager manager, TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardChangePINTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        for (OpenPGPSmartCardBackend backend : manager.getBackends())
        {
            performTestOn(backend);
        }
    }

    private void performTestOn(OpenPGPSmartCardBackend backend)
            throws CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Run SmartCardChangePINTest on backend " + backend.getName());
        List<OpenPGPSmartCard> cards = backend.listSmartCards();
        for (OpenPGPSmartCard card : cards)
        {
            // -DM System.out.println
            System.out.println("Change PINs on " + card.getCardType() + " " + card.getSerialNumber());
            try (OpenPGPSmartCard.Session session = card.open(true))
            {
                session.reset();
                testChangeAdminPIN(session);
                testChangeUserPIN(session);
            }
        }
    }

    private void testChangeAdminPIN(OpenPGPSmartCard.Session session)
            throws CardException
    {
        char[] oldAdminPin = properties.getAdminPin();
        isTrue("Cannot verify old admin PIN", session.checkAdminPIN(c -> oldAdminPin));

        char[] newAdminPin = "12131415".toCharArray();
        session.changeAdminPIN(c -> oldAdminPin, c -> newAdminPin);
        try
        {
            isTrue("Cannot verify new admin PIN after changing it", session.checkAdminPIN(c -> newAdminPin));
            isTrue("Old admin PIN erroneously still verifies", !session.checkAdminPIN(c -> oldAdminPin));
        }
        finally
        {
            // change back, so a failure does not leave the card with an unknown PIN
            session.changeAdminPIN(c -> newAdminPin, c -> oldAdminPin);
        }
        isTrue("Cannot verify admin PIN after changing it back", session.checkAdminPIN(c -> oldAdminPin));
    }

    private void testChangeUserPIN(OpenPGPSmartCard.Session session)
            throws CardException
    {
        char[] oldUserPIN = properties.getUserPin();
        isTrue("Cannot verify old user PIN", session.checkUserPIN(c -> oldUserPIN));

        // a wrong old PIN is refused and leaves the PIN as it was
        char[] newUserPIN = "121314".toCharArray();
        try
        {
            session.changeUserPIN(c -> "999999".toCharArray(), c -> newUserPIN);
            fail("User PIN changed with a wrong old PIN");
        }
        catch (CardException e)
        {
            // expected
        }
        isTrue("Rejected change altered the user PIN", session.checkUserPIN(c -> oldUserPIN));

        session.changeUserPIN(c -> oldUserPIN, c -> newUserPIN);
        try
        {
            isTrue("Cannot verify new user PIN after changing it", session.checkUserPIN(c -> newUserPIN));
            isTrue("Old user PIN erroneously still verifies", !session.checkUserPIN(c -> oldUserPIN));
        }
        finally
        {
            // change back, so a failure does not leave the card with an unknown PIN
            session.changeUserPIN(c -> newUserPIN, c -> oldUserPIN);
        }
        isTrue("Cannot verify user PIN after changing it back", session.checkUserPIN(c -> oldUserPIN));
    }
}
