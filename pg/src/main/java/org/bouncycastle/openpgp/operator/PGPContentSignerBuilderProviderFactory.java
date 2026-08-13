package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;

public interface PGPContentSignerBuilderProviderFactory
{
    PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            KeyPassphraseProvider keyPassphraseProvider,
            int hashAlgorithmId)
            throws PGPException;
}
