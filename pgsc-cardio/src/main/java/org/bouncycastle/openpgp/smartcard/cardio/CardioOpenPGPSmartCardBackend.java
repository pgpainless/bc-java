package org.bouncycastle.openpgp.smartcard.cardio;

import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.pgpainless.cardio.api.CardioManager;
import org.pgpainless.cardio.api.SmartCard;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CardioOpenPGPSmartCardBackend
        extends OpenPGPSmartCardBackend<CardioOpenPGPSmartCard>
{
    private final CardioManager cardioManager;
    private final JcaPGPKeyConverter keyConverter;

    public CardioOpenPGPSmartCardBackend(OpenPGPSmartCardImplementation implementation,
                                         JcaPGPKeyConverter converter)
    {
        this(implementation, converter, new CardioManager());
    }

    public CardioOpenPGPSmartCardBackend(OpenPGPSmartCardImplementation implementation,
                                         JcaPGPKeyConverter converter,
                                         CardioManager cardioManager)
    {
        super(implementation, converter);
        this.keyConverter = converter;
        this.cardioManager = cardioManager;
    }

    @Override
    public String getName()
    {
        return "Cardio";
    }

    JcaPGPKeyConverter getKeyConverter()
    {
        return keyConverter;
    }

    @Override
    public List<CardioOpenPGPSmartCard> listSmartCards()
            throws CardException, IOException
    {
        List<SmartCard> cards = cardioManager.listSmartCards();
        List<CardioOpenPGPSmartCard> bcCards = new ArrayList<>();
        for (Iterator<SmartCard> i = cards.iterator(); i.hasNext(); )
        {
            SmartCard card = i.next();
            bcCards.add(new CardioOpenPGPSmartCard(this, card.selectOpenPGP()));
        }
        return bcCards;
    }
}
