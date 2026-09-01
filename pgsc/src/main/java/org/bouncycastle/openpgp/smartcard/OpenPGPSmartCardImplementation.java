package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.operator.ExternalContentSignerBuilder;

public abstract class OpenPGPSmartCardImplementation
{
    protected final OpenPGPImplementation implementation;

    public OpenPGPSmartCardImplementation(OpenPGPImplementation implementation)
    {
        this.implementation = implementation;
    }

    public abstract PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            OpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException;

    public PGPContentSignerBuilderProvider providePGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            OpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId)
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
                return new ExternalContentSignerBuilder(
                        card.getSignatureKey(),
                        signingKey,
                        userPinProvider,
                        hashAlgorithmId,
                        digestCalculatorProvider);
            }
        };
    }

    public abstract String getName();
}
