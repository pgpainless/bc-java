package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PBESecretKeyDecryptorBuilderProvider
{
    PBESecretKeyDecryptorBuilder provide()
            throws PGPException;
}
