package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * OpenPGP certificates (TPKs - transferable public keys) are long-living structures that may change during
 * their lifetime. A key-holder may add new components like subkeys or identities, along with associated
 * binding self-signatures to the certificate and old components may expire / get revoked at some point.
 * Since any such changes may have an influence on whether a data signature is valid at a given time, or what subkey
 * should be used when generating an encrypted / signed message, an API is needed that provides a view on the
 * certificate that takes into consideration a relevant window in time.
 * <p>
 * Compared to a {@link PGPPublicKeyRing}, an {@link OpenPGPCertificate} has been evaluated at (or rather for)
 * a given evaluation time. It offers a clean API for accessing the key-holder's preferences at a specific
 * point in time and makes sure, that relevant self-signatures on certificate components are validated and verified.
 *
 * @see <a href="https://openpgp.dev/book/certificates.html#">OpenPGP for Application Developers - Chapter 4</a>
 * for background information on the terminology used in this class.
 */
public class OpenPGPCertificate
{
    protected final PGPPublicKeyRing rawCert;
    protected final Date evaluationTime;

    protected final OpenPGPPrimaryKey primaryKey;
    protected final Map<KeyIdentifier, OpenPGPSubkey> subkeys = new HashMap<>();

    public OpenPGPCertificate(PGPPublicKeyRing rawCert)
    {
        this(rawCert, new Date());
    }

    public OpenPGPCertificate(PGPPublicKeyRing rawCert, Date evaluationTime)
    {
        this.rawCert = rawCert;
        this.evaluationTime = evaluationTime;

        Iterator<PGPPublicKey> rawKeys = rawCert.getPublicKeys();
        PGPPublicKey rawPrimaryKy = rawKeys.next();

        this.primaryKey = evaluatePrimaryKey(rawPrimaryKy, evaluationTime);

        while (rawKeys.hasNext())
        {
            PGPPublicKey rawSubkey = rawKeys.next();
            subkeys.put(new KeyIdentifier(rawSubkey), evaluateSubkey(rawSubkey, primaryKey));
        }
    }

    private OpenPGPPrimaryKey evaluatePrimaryKey(PGPPublicKey pk, Date evaluationTime) throws PGPException {
        enforceKeyVersion(pk);

        List<PGPSignature> directKeySelfSignatures = new ArrayList<>();
        List<PGPSignature> directKey3rdPartySignatures = new ArrayList<>();

        // Sort direct-key signatures by issuer
        Iterator<PGPSignature> directKeySigs = pk.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        while (directKeySigs.hasNext())
        {
            PGPSignature dkSig = directKeySigs.next();
            if (!KeyIdentifier.matches(dkSig.getKeyIdentifiers(), pk))
            {
                // is 3rd-party-issued sig
                directKey3rdPartySignatures.add(dkSig);
            }
            else // is self-sig
            {
                directKeySelfSignatures.add(dkSig);
            }
        }

        // Sort by creation time, new -> old
        directKeySelfSignatures.sort(Comparator.comparing(PGPSignature::getCreationTime).reversed());

        // Find latest signature not newer than evaluation time
        Iterator<PGPSignature> it = directKeySelfSignatures.iterator();
        while (it.hasNext())
        {
            PGPSignature sig = it.next();
            // Skip over sigs in the future
            if (sig.getCreationTime().after(evaluationTime))
            {
                continue;
            }

            sig.init(new BcPGPContentVerifierBuilderProvider(), pk);
            boolean isSignatureCorrect = sig.verifyCertification(pk);
            if (isSignatureCorrect)
            {
                
            }
        }

        else
        {

        }
    }

    private OpenPGPSubkey evaluateSubkey(PGPPublicKey rawSubkey, OpenPGPPrimaryKey primaryKey)
    {
        enforceKeyVersion(rawSubkey);

    }

    private void enforceKeyVersion(PGPPublicKey key)
    {
        enforceKeyVersion(key, PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6);
    }

    private void enforceKeyVersion(PGPPublicKey key, int minVersion, int maxVersion)
    {
        final int version = key.getVersion();
        if (version < minVersion || version > maxVersion)
        {
            throw new UnsupportedPacketVersionException("Key " + key.getKeyIdentifier() + " has unsupported version " + version);
        }
    }

    public OpenPGPCertificate evaluateFor(PGPSignature signature, PGPPublicKeyRing rawCert)
    {
        // TODO: Sanitize signature creation time
        return new OpenPGPCertificate(rawCert, signature.getCreationTime());
    }

    public OpenPGPCertificate reevaluateAt(Date evaluationTime)
    {
        return new OpenPGPCertificate(rawCert, evaluationTime);
    }

    public OpenPGPPrimaryKey getPrimaryKey()
    {
        return primaryKey;
    }

    public Date getEvaluationTime()
    {
        return evaluationTime;
    }

    public PGPPublicKeyRing getRawCertificate()
    {
        return rawCert;
    }

    /**
     * A component key is either a primary key, or a subkey.
     *
     * @see <a href="https://openpgp.dev/book/certificates.html#layers-of-keys-in-openpgp">
     *     OpenPGP for Application Developers - Layers of keys in OpenPGP</a>
     */
    public static class OpenPGPComponentKey
    {
        protected final OpenPGPCertificate certificate;

        public OpenPGPComponentKey(OpenPGPCertificate certificate)
        {
            this.certificate = certificate;
        }

        public KeyIdentifier getKeyIdentifier()
        {
            return null; // TODO: Fix
        }

        public Builder builder(PGPContentVerifierBuilderProvider verifierBuilderProvider)
        {
            return new Builder(verifierBuilderProvider);
        }

        public static class Builder
        {
            private final PGPContentVerifierBuilderProvider verifierBuilderProvider;

            public Builder(PGPContentVerifierBuilderProvider verifierBuilderProvider)
            {
                this.verifierBuilderProvider = verifierBuilderProvider;
            }

        }
    }

    public static class OpenPGPPrimaryKey extends OpenPGPComponentKey
    {
        protected List<OpenPGPIdentityComponent> identityComponents;

        public OpenPGPPrimaryKey(OpenPGPCertificate certificate)
        {
            super(certificate);
        }
    }

    public static class OpenPGPSubkey extends OpenPGPComponentKey
    {
        public OpenPGPSubkey(OpenPGPCertificate certificate)
        {
            super(certificate);
        }

        public OpenPGPPrimaryKey getPrimaryKey()
        {
            return certificate.getPrimaryKey();
        }
    }

    public static class OpenPGPIdentityComponent
    {
        public OpenPGPPrimaryKey getPrimaryKey()
        {
            return null;
        }
    }

    public static class OpenPGPUserId extends OpenPGPIdentityComponent
    {
        public OpenPGPUserId(String userId, OpenPGPPrimaryKey primaryKey)
    }

    public static class OpenPGPUserAttribute extends OpenPGPIdentityComponent
    {

    }
}
