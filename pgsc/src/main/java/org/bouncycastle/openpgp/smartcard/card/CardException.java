package org.bouncycastle.openpgp.smartcard.card;

import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;

public class CardException
        extends Exception
{
    public CardException()
    {
        super();
    }

    public CardException(String message)
    {
        super(message);
    }

    public CardException(Throwable cause)
    {
        super(cause);
    }

    public CardException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public CardException(OpenPGPSmartCard card, String message, Throwable cause)
    {
        super("Exception on card " + card.getCardType() + " (" + card.getSerialNumber() + "): " + message, cause);
    }
}
