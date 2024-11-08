package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

import java.util.Date;

/**
 * An OpenPGP signature.
 * This is a wrapper around {@link PGPSignature} which tracks the verification state of the signature.
 */
public class OpenPGPSignature
{
    protected final PGPSignature signature;
    protected boolean isTested = false;
    protected boolean isCorrect = false;

    public OpenPGPSignature(PGPSignature signature)
    {
        this.signature = signature;
    }

    public boolean isTestedCorrect()
    {
        return isTested && isCorrect;
    }

    public Date getCreationTime()
    {
        return signature.getCreationTime();
    }

    public Date getExpirationTime()
    {
        PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
        if (hashed == null)
        {
            // v3 sigs have no expiration
            return null;
        }
        long exp = hashed.getSignatureExpirationTime();
        if (exp < 0)
        {
            throw new RuntimeException("Negative expiration time");
        }

        if (exp == 0L)
        {
            // Explicit or implicit no expiration
            return null;
        }

        return new Date(getCreationTime().getTime() + 1000 * exp);
    }

    public boolean isCertification()
    {
        return signature.isCertification();
    }

    /**
     * An {@link OpenPGPSignature} made over data (e.g. a message).
     * An {@link OpenPGPDataSignature} CANNOT live on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPDataSignature
            extends OpenPGPSignature
    {
        public OpenPGPDataSignature(PGPSignature signature)
        {
            super(signature);
        }
    }
}
