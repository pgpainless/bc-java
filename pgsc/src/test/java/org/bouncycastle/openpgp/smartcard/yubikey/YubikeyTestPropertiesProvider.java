package org.bouncycastle.openpgp.smartcard.yubikey;

import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;

public class YubikeyTestPropertiesProvider
    extends SmartCardTestPropertiesProvider
{
    private static final String DEF_PROP_FILE = "yubikey.properties";

    @Override
    public SmartCardTestProperties getCardA()
    {
        try
        {
            return SmartCardTestProperties.fromFile(DEF_PROP_FILE);
        }
        catch (FileNotFoundException e)
        {
            return null;
        }
    }

    @Override
    public SmartCardTestProperties getCardB()
    {
        // TODO: Implement
        return null;
    }

    public List<SmartCardTestProperties> getCards()
    {
        List<SmartCardTestProperties> cards = new ArrayList<>();
        SmartCardTestProperties cardA = getCardA();
        if (cardA != null)
        {
            cards.add(cardA);
        }
        SmartCardTestProperties cardB = getCardB();
        if (cardB != null)
        {
            cards.add(cardB);
        }
        return cards;
    }
}
