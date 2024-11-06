package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class OpenPGPKey
        extends OpenPGPCertificate
{
    private final PGPSecretKeyRing rawKey;

    public OpenPGPKey(PGPSecretKeyRing rawKey,
                      PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPException
    {
        this(rawKey, new Date(), contentVerifierBuilderProvider);
    }

    public OpenPGPKey(PGPSecretKeyRing rawKey,
                      Date evaluationTime,
                      PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPException
    {
        super(asCert(rawKey), evaluationTime, contentVerifierBuilderProvider);
        this.rawKey = rawKey;
    }

    private static PGPPublicKeyRing asCert(PGPSecretKeyRing key)
    {
        // TODO: Replace with dedicated PGPSecretKeyRing method
        Iterator<PGPPublicKey> pubKeyIt = key.getPublicKeys();
        List<PGPPublicKey> pubkeys = new ArrayList<>();
        while (pubKeyIt.hasNext())
        {
            pubkeys.add(pubKeyIt.next());
        }
        return new PGPPublicKeyRing(pubkeys);
    }

    public PGPSecretKeyRing getRawKey()
    {
        return rawKey;
    }
}
