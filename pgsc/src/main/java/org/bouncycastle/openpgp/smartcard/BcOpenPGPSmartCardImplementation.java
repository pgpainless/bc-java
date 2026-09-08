package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.operator.bc.BcSmartCardPublicKeyDataDecryptorFactory;

public class BcOpenPGPSmartCardImplementation
        extends OpenPGPSmartCardImplementation
{
    public BcOpenPGPSmartCardImplementation()
    {
        this(new BcOpenPGPImplementation());
    }

    public BcOpenPGPSmartCardImplementation(BcOpenPGPImplementation implementation)
    {
        super(implementation);
    }

    @Override
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            OpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        return new BcSmartCardPublicKeyDataDecryptorFactory<>(secretKey, card, userPinProvider);
    }

    @Override
    public String getName()
    {
        return "BC";
    }
}
