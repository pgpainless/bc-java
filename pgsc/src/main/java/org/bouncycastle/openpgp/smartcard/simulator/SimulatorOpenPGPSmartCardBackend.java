package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.operator.bc.BcSmartCardPublicKeyDataDecryptorFactory;

import java.util.ArrayList;
import java.util.List;

public class SimulatorOpenPGPSmartCardBackend
        extends OpenPGPSmartCardBackend<SimulatorOpenPGPSmartCard>
{
    private final List<SimulatorOpenPGPSmartCard> smartCards = new ArrayList<>();

    public SimulatorOpenPGPSmartCardBackend(OpenPGPImplementation implementation)
    {
        super(implementation);
    }

    @Override
    public String getName()
    {
        return "Simulator";
    }

    public SimulatorOpenPGPSmartCardBackend addSmartCard(SimulatorOpenPGPSmartCard card)
    {
        this.smartCards.add(card);
        return this;
    }

    @Override
    public List<SimulatorOpenPGPSmartCard> listSmartCards()
    {
        return smartCards;
    }

    @Override
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey key,
            SimulatorOpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        return new BcSmartCardPublicKeyDataDecryptorFactory<>(key, card, userPinProvider);
        //PGPPrivateKey softwareKey = card.getSoftwareKey(key, userPinProvider);

        //return new BcPublicKeyDataDecryptorFactory(new PGPKeyPair(key.getPGPPublicKey(), softwareKey));
    }
}
