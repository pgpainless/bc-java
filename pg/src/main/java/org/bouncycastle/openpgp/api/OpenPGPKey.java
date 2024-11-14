package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

public class OpenPGPKey
        extends OpenPGPCertificate
{

    public OpenPGPKey(PGPSecretKeyRing rawKey,
                      PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
    {
        super(rawKey, contentVerifierBuilderProvider);
    }

    @Override
    public PGPSecretKeyRing getPGPKeyRing()
    {
        return (PGPSecretKeyRing) super.getPGPKeyRing();
    }
}
