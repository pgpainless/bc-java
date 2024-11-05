package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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

    private OpenPGPPrimaryKey evaluatePrimaryKey(PGPPublicKey pk, Date evaluationTime)
            throws PGPException
    {
        enforceKeyVersion(pk);
        Signatures signatures = Signatures.on(pk);

        Signatures directKeySelfSigs = signatures
                .ofTypes(PGPSignature.DIRECT_KEY)
                .issuedBy(pk)
                .createdAtOrBefore(evaluationTime);
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

    public static class Signatures
    {

        // descending by creation time (newest first)
        private final List<PGPSignature> signatures = new ArrayList<>();

        public static Signatures from(List<PGPSignature> unsorted)
        {
            Signatures sigs = new Signatures(unsorted);
            sigs.signatures.sort(Comparator.comparing(PGPSignature::getCreationTime).reversed());
            return sigs;
        }

        public static Signatures on(PGPPublicKey key)
        {
            Iterator<PGPSignature> iterator = key.getSignatures();
            List<PGPSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                list.add(iterator.next());
            }
            return Signatures.from(list);
        }

        private Signatures(List<PGPSignature> signatures)
        {
            this.signatures.addAll(signatures);
        }

        /**
         * Return all signatures.
         *
         * @return signatures
         */
        public List<PGPSignature> get()
        {
            return Collections.unmodifiableList(signatures);
        }

        /**
         * Return the current-most {@link PGPSignature} that matches the criteria.
         *
         * @return signature or null
         */
        public PGPSignature current()
        {
            return signatures.isEmpty() ? null : signatures.get(0);
        }

        public Signatures directKeySelfSignatures(OpenPGPPrimaryKey key)
        {
            return ofTypes(PGPSignature.DIRECT_KEY)
                    .issuedBy(key.getKeyIdentifier())
                    .wellformed()
                    .createdAtOrBefore(key.certificate.getEvaluationTime())
                    .correct(key);
        }

        private Signatures correct(OpenPGPPrimaryKey key)
        {
            return this; // TODO: Implement
        }

        /**
         * Return a {@link Signatures list} containing all {@link PGPSignature PGPSignatures} whose creation time is
         * before or equal to the passed in evaluationTime.
         * If all {@link PGPSignature PGPSignatures} were created after the evaluationTime, return an
         * empty {@link Signatures list}.
         *
         * @param evaluationTime evaluation time
         * @return list of signatures created before or at evaluation time
         */
        public Signatures createdAtOrBefore(Date evaluationTime)
        {
            // Find index of most recent signature that was created before or at evaluation time
            //  and return sublist from this index
            for (int i = 0; i < signatures.size(); i++)
            {
                PGPSignature sig = signatures.get(i);
                if (!sig.getCreationTime().after(evaluationTime))
                {
                    return new Signatures(signatures.subList(i, signatures.size()));
                }
            }
            return new Signatures(Collections.emptyList());
        }

        public Signatures issuedBy(PGPPublicKey key)
        {
            return issuedBy(key.getKeyIdentifier());
        }

        public Signatures issuedBy(KeyIdentifier keyIdentifier)
        {
            List<PGPSignature> matching = new ArrayList<>();
            for (PGPSignature sig : signatures)
            {
                if (KeyIdentifier.matches(sig.getKeyIdentifiers(), keyIdentifier, true))
                {
                    matching.add(sig);
                }
            }
            return new Signatures(matching);
        }

        public Signatures notIssuedBy(PGPPublicKey key)
        {
            return notIssuedBy(key.getKeyIdentifier());
        }

        public Signatures notIssuedBy(KeyIdentifier keyIdentifier)
        {
            List<PGPSignature> matching = new ArrayList<>();
            for (PGPSignature sig : signatures)
            {
                if (!KeyIdentifier.matches(sig.getKeyIdentifiers(), keyIdentifier, true))
                {
                    matching.add(sig);
                }
            }
            return new Signatures(matching);
        }

        public Signatures ofTypes(int... types)
        {
            List<PGPSignature> matching = new ArrayList<>();
            outer: for (PGPSignature sig : signatures)
            {
                for (int type : types)
                {
                    if (sig.getSignatureType() == type)
                    {
                        matching.add(sig);
                        continue outer;
                    }
                }
            }
            return new Signatures(matching);
        }

        public Signatures wellformed()
        {
            List<PGPSignature> wellformed = new ArrayList<>();
            for (PGPSignature sig : signatures)
            {
                if (sig.getHashedSubPackets().getSignatureCreationTime() == null)
                {
                    continue; // Missing hashed creation time - malformed
                }

                NotationData[] hashedNotations = sig.getHashedSubPackets().getNotationDataOccurrences();
                for (NotationData notation : hashedNotations)
                {
                    if (!NotationPredicate.fromNotationRegistry(new NotationRegistry())
                            .accept(notation))
                    {
                        continue; // Unknown critical notation
                    }
                }

                wellformed.add(sig);
            }
            return new Signatures(wellformed);
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
