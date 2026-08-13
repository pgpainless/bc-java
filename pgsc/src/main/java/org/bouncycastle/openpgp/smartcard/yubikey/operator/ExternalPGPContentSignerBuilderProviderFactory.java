package org.bouncycastle.openpgp.smartcard.yubikey.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;

public interface ExternalPGPContentSignerBuilderProviderFactory<T extends OpenPGPSmartCard>
{
    PGPContentSignerBuilderProvider provideExternalPGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            T card,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId,
            OpenPGPImplementation implementation) throws PGPException;
}
