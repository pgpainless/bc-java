package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

import java.util.Date;
import java.util.List;

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

    public PGPSignature getSignature()
    {
        return signature;
    }

    /**
     * Return a {@link List} of possible {@link KeyIdentifier} candidates.
     *
     * @return key identifier candidates
     */
    public List<KeyIdentifier> getKeyIdentifiers()
    {
        return signature.getKeyIdentifiers();
    }

    /**
     * Return the most expressive {@link KeyIdentifier} from available candidates.
     *
     * @return most expressive key identifier
     */
    public KeyIdentifier getKeyIdentifier()
    {
        List<KeyIdentifier> identifiers = getKeyIdentifiers();
        if (identifiers.isEmpty())
        {
            return null;
        }
        if (identifiers.size() == 1)
        {
            return identifiers.get(0);
        }

        // Find most expressive identifier
        for (KeyIdentifier identifier : identifiers)
        {
            if (!identifier.isWildcard() && identifier.getFingerprint() != null)
            {
                return identifier;
            }
        }

        // Find non-wildcard identifier
        for (KeyIdentifier identifier : identifiers)
        {
            if (!identifier.isWildcard())
            {
                return identifier;
            }
        }
        // else return first identifier
        return identifiers.get(0);
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

    public boolean isEffectiveAt(Date evaluationTime)
    {
        if (isHardRevocation())
        {
            // hard revocation is valid at all times
            return true;
        }

        // creation <= eval < expiration
        Date creation = getCreationTime();
        Date expiration = getExpirationTime();
        return !evaluationTime.before(creation) && (expiration == null || evaluationTime.before(expiration));
    }

    public boolean isHardRevocation()
    {
        return signature.isHardRevocation();
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
