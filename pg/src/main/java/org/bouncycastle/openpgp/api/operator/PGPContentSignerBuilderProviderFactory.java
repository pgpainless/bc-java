package org.bouncycastle.openpgp.api.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;

public interface PGPContentSignerBuilderProviderFactory
{
    PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            KeyPassphraseProvider keyPassphraseProvider,
            int hashAlgorithmId)
            throws PGPException;
}
