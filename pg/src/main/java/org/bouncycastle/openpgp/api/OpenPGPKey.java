package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

public class OpenPGPKey
        extends OpenPGPCertificate
{
    private final PGPSecretKeyRing rawKey;

    public OpenPGPKey(PGPSecretKeyRing rawKey,
                      PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
    {
        super(rawKey, contentVerifierBuilderProvider);
        this.rawKey = rawKey;
    }

    public PGPSecretKeyRing getRawKey()
    {
        return rawKey;
    }
}
