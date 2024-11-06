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
import java.util.Optional;
import java.util.function.BinaryOperator;

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
    private final PGPContentVerifierBuilderProvider contentVerifierBuilderProvider;

    protected final PGPPublicKeyRing rawCert;
    protected final Date evaluationTime;

    protected final OpenPGPPrimaryKey primaryKey;
    protected final Map<KeyIdentifier, OpenPGPSubkey> subkeys = new HashMap<>();

    public OpenPGPCertificate(PGPPublicKeyRing rawCert,
                              PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPException
    {
        this(rawCert, new Date(), contentVerifierBuilderProvider);
    }

    public OpenPGPCertificate(PGPPublicKeyRing rawCert,
                              Date evaluationTime,
                              PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
            throws PGPException
    {
        this.contentVerifierBuilderProvider = contentVerifierBuilderProvider;

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
        Signatures signatures = Signatures.on(pk, contentVerifierBuilderProvider);

        Signatures directKeySelfSigs = signatures
                .ofTypes(PGPSignature.DIRECT_KEY)
                .wellformed()
                .issuedBy(pk)
                .createdAtOrBefore(evaluationTime);
        OpenPGPSignature directKeySelfSignature = findCorrectKeySignature(directKeySelfSigs, pk, pk);

        Signatures keyRevocationSelfSigs = signatures
                .ofTypes(PGPSignature.KEY_REVOCATION)
                .wellformed()
                .issuedBy(pk)
                .createdAtOrBefore(evaluationTime);
        OpenPGPSignature keyRevocationSelfSignature = findCorrectKeySignature(keyRevocationSelfSigs, pk, pk);

        return new OpenPGPPrimaryKey(this);
    }

    private OpenPGPSignature findCorrectKeySignature(Signatures candidates, PGPPublicKey issuer, PGPPublicKey target)
    {
        OpenPGPSignature correctSignature = null;
        for (OpenPGPSignature sig : candidates.get())
        {
            if (sig.isTestedCorrect())
            {
                correctSignature = sig;
                break;
            }

            if (!sig.isTested)
            {
                try
                {
                    boolean correct = sig.verifyKeySignature(issuer, target);
                    if (correct)
                    {
                        correctSignature = sig;
                        break;
                    }
                }
                catch (PGPException e)
                {
                    continue;
                }
            }
        }
        return correctSignature;
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
        return new OpenPGPCertificate(rawCert, signature.getCreationTime(), contentVerifierBuilderProvider);
    }

    public OpenPGPCertificate reevaluateAt(Date evaluationTime)
    {
        return new OpenPGPCertificate(rawCert, evaluationTime, contentVerifierBuilderProvider);
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

        // Sort signatures by hard-revocation-ness. Hard revocation are sorted to the front of the list
        private static final Comparator<OpenPGPSignature> hardRevocationComparator = (one, two) ->
        {
            boolean oneHard = one.signature.isHardRevocation();
            boolean twoHard = two.signature.isHardRevocation();
            return oneHard == twoHard ? 0 : (oneHard ? -1 : 1);
        };

        // descending by creation time (newest first)
        private final List<OpenPGPSignature> signatures = new ArrayList<>();

        public static Signatures from(List<OpenPGPSignature> unsorted)
        {
            Signatures sigs = new Signatures(unsorted);
            sigs.signatures.sort(Comparator
                    .comparing(OpenPGPSignature::getCreationTime)
                    .reversed()
                    .thenComparing(hardRevocationComparator));
            return sigs;
        }

        public static Signatures on(PGPPublicKey key, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            Iterator<PGPSignature> iterator = key.getSignatures();
            List<OpenPGPSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                list.add(new OpenPGPSignature(iterator.next(), contentVerifierBuilderProvider));
            }
            return Signatures.from(list);
        }

        private Signatures(List<OpenPGPSignature> signatures)
        {
            this.signatures.addAll(signatures);
        }

        /**
         * Return all signatures.
         *
         * @return signatures
         */
        public List<OpenPGPSignature> get()
        {
            return Collections.unmodifiableList(signatures);
        }

        /**
         * Return the current-most {@link PGPSignature} that matches the criteria.
         *
         * @return signature or null
         */
        public OpenPGPSignature current()
        {
            return signatures.isEmpty() ? null : signatures.get(0);
        }

        /**
         * Return a {@link Signatures list} containing all {@link PGPSignature PGPSignatures} whose creation time is
         * before or equal to the passed in evaluationTime, or who are hard revocations.
         * If all {@link PGPSignature PGPSignatures} were created after the evaluationTime, return an
         * empty {@link Signatures list}.
         *
         * @param evaluationTime evaluation time
         * @return list of signatures which were created before or at evaluation time or which are hard revocations
         */
        public Signatures createdAtOrBefore(Date evaluationTime)
        {
            List<OpenPGPSignature> matching = new ArrayList<>();
            // Find index of most recent signature that was created before or at evaluation time
            //  and return sublist from this index
            for (OpenPGPSignature sig : signatures)
            {
                // hard revocations are effective at any time
                if (sig.signature.isHardRevocation())
                {
                    matching.add(sig);
                    continue;
                }

                // sig was created at or before eval time
                if (!sig.getCreationTime().after(evaluationTime))
                {
                    matching.add(sig);
                }
            }

            return new Signatures(matching);
        }

        public Signatures issuedBy(PGPPublicKey key)
        {
            return issuedBy(key.getKeyIdentifier());
        }

        public Signatures issuedBy(KeyIdentifier keyIdentifier)
        {
            List<OpenPGPSignature> matching = new ArrayList<>();
            for (OpenPGPSignature sig : signatures)
            {
                if (KeyIdentifier.matches(sig.signature.getKeyIdentifiers(), keyIdentifier, true))
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
            List<OpenPGPSignature> matching = new ArrayList<>();
            for (OpenPGPSignature sig : signatures)
            {
                if (!KeyIdentifier.matches(sig.signature.getKeyIdentifiers(), keyIdentifier, true))
                {
                    matching.add(sig);
                }
            }
            return new Signatures(matching);
        }

        public Signatures ofTypes(int... types)
        {
            List<OpenPGPSignature> matching = new ArrayList<>();
            outer: for (OpenPGPSignature sig : signatures)
            {
                for (int type : types)
                {
                    if (sig.signature.getSignatureType() == type)
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
            List<OpenPGPSignature> wellformed = new ArrayList<>();
            for (OpenPGPSignature sig : signatures)
            {
                if (sig.signature.getHashedSubPackets().getSignatureCreationTime() == null)
                {
                    continue; // Missing hashed creation time - malformed
                }

                NotationData[] hashedNotations = sig.signature.getHashedSubPackets().getNotationDataOccurrences();
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
        {

        }
    }

    public static class OpenPGPUserAttribute extends OpenPGPIdentityComponent
    {

    }

    public static class OpenPGPSignature
    {
        private final PGPContentVerifierBuilderProvider contentVerifierBuilderProvider;
        private final PGPSignature signature;
        private boolean isTested = false;
        private boolean isCorrect = false;

        public OpenPGPSignature(PGPSignature signature, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            this.contentVerifierBuilderProvider = contentVerifierBuilderProvider;
            this.signature = signature;
        }

        public boolean isTestedCorrect()
        {
            return isTested && isCorrect;
        }

        public boolean verifyKeySignature(PGPPublicKey issuer, PGPPublicKey target)
                throws PGPException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer);
                isCorrect = signature.verifyCertification(target);
                return isCorrect;
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw e;
            }
        }

        public Date getCreationTime()
        {
            return signature.getCreationTime();
        }

        public Date getExpirationTime() {
            return null;
        }
    }

    public static class OpenPGPSignatureChain
    {
        private final List<Link> chainLinks = new ArrayList<>();

        public Link getRoot()
        {
            return chainLinks.get(0);
        }

        public Link getHead()
        {
            return chainLinks.get(chainLinks.size() - 1);
        }

        /**
         * Return the date since which this signature chain is valid.
         * This is the creation time of the most recent link in the chain.
         *
         * @return most recent signature creation time
         */
        public Date getSince()
        {
            // Find most recent chain link
            return chainLinks.stream()
                    .map(it -> it.signature)
                    .max(Comparator.comparing(OpenPGPSignature::getCreationTime))
                    .map(OpenPGPSignature::getCreationTime)
                    .orElse(null);
        }

        /**
         * Return the date until which the chain link is valid.
         * This is the earliest expiration time of any signature in the chain.
         *
         * @return earliest expiration time
         */
        public Date getUntil()
        {
            return getHead().until();
        }

        public static abstract class Link
        {
            protected final OpenPGPSignature signature;

            public Link(OpenPGPSignature signature)
            {
                this.signature = signature;
            }

            public Date since()
            {
                return signature.getCreationTime();
            }

            public Date until()
            {
                return signature.getExpirationTime();
            }
        }

        public static class Valid extends Link
        {
            public Valid(OpenPGPSignature signature) {
                super(signature);
            }
        }

        public static class Expired extends Link
        {
            public Expired(OpenPGPSignature signature) {
                super(signature);
            }
        }

        public static class Revoked extends Link
        {
            public Revoked(OpenPGPSignature signature) {
                super(signature);
            }
        }
    }

    public static class MultiDimensionalLazyCachingTemporalSuperDataStructure
    {

    }
}
