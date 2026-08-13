package org.bouncycastle.openpgp.smartcard.yubikey.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyOpenPGPSmartCard;

public class YubikeyPGPContentSignerBuilderProviderFactory
        implements ExternalPGPContentSignerBuilderProviderFactory<YubikeyOpenPGPSmartCard>
{
    @Override
    public PGPContentSignerBuilderProvider provideExternalPGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            YubikeyOpenPGPSmartCard smartCard,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId,
            OpenPGPImplementation implementation)
            throws PGPException
    {
        PGPDigestCalculatorProvider digestCalculatorProvider = implementation.pgpDigestCalculatorProvider();
        return new PGPContentSignerBuilderProvider(hashAlgorithmId)
        {
            @Override
            public PGPContentSignerBuilder get(PGPPublicKey signingPubKey)
            {
                if (!signingKey.getPGPPublicKey().getKeyIdentifier().matchesExplicit(signingPubKey.getKeyIdentifier()))
                {
                    throw new IllegalArgumentException("Wrong public key provided.");
                }

                return get(signingKey);
            }

            @Override
            public PGPContentSignerBuilder get(OpenPGPKey.OpenPGPSecretKey signingKey)
            {
                return new YubikeyPGPContentSignerBuilder(signingKey, smartCard, userPinProvider, digestCalculatorProvider, hashAlgorithmId);
            }
        };
    }
}
