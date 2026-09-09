package org.bouncycastle.openpgp.smartcard.card;

import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;

public class CardPinException
        extends CardException
{
    public CardPinException(OpenPGPSmartCard card, String message, Throwable cause)
    {
        super(card, message, cause);
    }
}
