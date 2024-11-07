package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

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
    protected Date evaluationTime;

    protected final PGPPublicKeyRing rawCert;
    protected final OpenPGPPrimaryKey primaryKey;
    protected final Map<KeyIdentifier, OpenPGPSubkey> subkeys;
    protected final LazyTemporalSignatureChainCache certificationCache;

    public OpenPGPCertificate(PGPPublicKeyRing rawCert,
                              PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
    {
        this(rawCert, new Date(), contentVerifierBuilderProvider);
    }

    public OpenPGPCertificate(PGPPublicKeyRing rawCert,
                              Date evaluationTime,
                              PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
    {
        this.certificationCache = new LazyTemporalSignatureChainCache(contentVerifierBuilderProvider);

        this.rawCert = rawCert;
        this.evaluationTime = evaluationTime;

        Iterator<PGPPublicKey> rawKeys = rawCert.getPublicKeys();
        PGPPublicKey rawPrimaryKey = rawKeys.next();
        this.primaryKey = new OpenPGPPrimaryKey(rawPrimaryKey, this);
        certificationCache.cachePrimaryKey(primaryKey);

        this.subkeys = new HashMap<>();
        while (rawKeys.hasNext())
        {
            PGPPublicKey rawSubkey = rawKeys.next();
            OpenPGPSubkey subkey = new OpenPGPSubkey(rawSubkey, this);
            subkeys.put(new KeyIdentifier(rawSubkey), subkey);
            certificationCache.cacheSubkey(subkey);
        }
    }

    /**
     * Set the evaluation date of the certificate to the creation time of the signature.
     *
     * @param signature signature
     */
    public void setEvaluationDateFor(PGPSignature signature)
    {
        // TODO: Sanitize signature creation time
        setEvaluationDate(signature.getCreationTime());
    }

    /**
     * Set the evaluation date of the certificate to the given time.
     *
     * @param evaluationTime evaluation date
     */
    public void setEvaluationDate(Date evaluationTime)
    {
        this.evaluationTime = evaluationTime;
    }

    /**
     * Return the primary key of the certificate.
     *
     * @return primary key
     */
    public OpenPGPPrimaryKey getPrimaryKey()
    {
        return primaryKey;
    }

    /**
     * Return the evaluation time of the certificate.
     *
     * @return evaluation time
     */
    public Date getEvaluationTime()
    {
        return evaluationTime;
    }

    /**
     * Return the {@link PGPPublicKeyRing} that this certificate is based on.
     *
     * @return underlying public key ring
     */
    public PGPPublicKeyRing getRawCertificate()
    {
        return rawCert;
    }

    public boolean isBound(OpenPGPCertificateComponent component)
    {
        try
        {
            return certificationCache.getSignatureChainFor(component, evaluationTime)
                    .isValid(certificationCache.contentVerifierBuilderProvider);
        }
        catch (PGPException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Collection of signatures on which different filter steps can be applied.
     * Signatures are sorted first by creation time (newest first), then by revocation-hardness.
     * Iterating through the signatures therefore first returns hard revocation signatures,
     * then signatures can be tried newest to oldest.
     */
    public static class Signatures
    {

        // Sort signatures by hard-revocation-ness. Hard revocation are sorted to the front of the list
        private static final Comparator<OpenPGPComponentSignature> hardRevocationComparator = (one, two) ->
        {
            boolean oneHard = one.signature.isHardRevocation();
            boolean twoHard = two.signature.isHardRevocation();
            return oneHard == twoHard ? 0 : (oneHard ? -1 : 1);
        };

        // descending by creation time (newest first)
        private final List<OpenPGPComponentSignature> signatures = new ArrayList<>();

        /**
         * Create a collection of {@link OpenPGPComponentSignature certificate signatures} from an unsorted list of
         * {@link PGPSignature PGPSignatures}.
         *
         * @param unsorted unsorted list
         * @return sorted collection
         */
        public static Signatures from(List<OpenPGPComponentSignature> unsorted)
        {
            Signatures sigs = new Signatures(unsorted);
            sigs.signatures.sort(Comparator
                    .comparing(OpenPGPComponentSignature::getCreationTime)
                    .reversed()
                    .thenComparing(hardRevocationComparator));
            return sigs;
        }

        /**
         * Filter for key-self-signatures on the given key.
         *
         * @param key key
         * @return self signatures over the key
         */
        public static Signatures keySignaturesOn(OpenPGPComponentKey key)
        {
            Iterator<PGPSignature> iterator = key.rawPubkey.getSignatures();
            List<OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPComponentKey issuer = key.getCertificate().getComponentKey(sig.getKeyIdentifiers());

                list.add(new OpenPGPComponentSignature(sig, issuer, key));
            }
            return Signatures.from(list);
        }

        /**
         * Filter for self-signatures on the given primary key and over the given user id.
         *
         * @param key primary key
         * @param userId user-id
         * @return self-signatures over the user-id
         */
        public static Signatures userIdSignaturesOn(OpenPGPPrimaryKey key, String userId)
        {
            Iterator<PGPSignature> iterator = key.rawPubkey.getSignaturesForID(userId);
            List<OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPComponentKey issuer = key.getCertificate().getComponentKey(sig.getKeyIdentifiers());

                list.add(new OpenPGPComponentSignature(sig, issuer, key));
            }
            return Signatures.from(list);
        }

        /**
         * Filter for self-signatures on the given primary key and over the given userAttribute.
         *
         * @param key primary key
         * @param userAttribute user-attribute
         * @return self-signatures over the user-attribute
         */
        public static Signatures userAttributeSignaturesOn(OpenPGPPrimaryKey key, PGPUserAttributeSubpacketVector userAttribute)
        {
            Iterator<PGPSignature> iterator = key.rawPubkey.getSignaturesForUserAttribute(userAttribute);
            List<OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPComponentKey issuer = key.getCertificate().getComponentKey(sig.getKeyIdentifiers());

                list.add(new OpenPGPComponentSignature(sig, issuer, key));
            }
            return Signatures.from(list);
        }

        /**
         * Private constructor.
         * Expects the signatures list to be sorted.
         * @param signatures sorted list
         */
        private Signatures(List<OpenPGPComponentSignature> signatures)
        {
            this.signatures.addAll(signatures);
        }

        /**
         * Return all signatures.
         *
         * @return signatures
         */
        public List<OpenPGPComponentSignature> get()
        {
            return Collections.unmodifiableList(signatures);
        }

        /**
         * Return the current-most {@link PGPSignature} that matches the criteria.
         *
         * @return signature or null
         */
        public OpenPGPComponentSignature current()
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
            List<OpenPGPComponentSignature> matching = new ArrayList<>();
            // Find index of most recent signature that was created before or at evaluation time
            //  and return sublist from this index
            for (OpenPGPComponentSignature sig : signatures)
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
            List<OpenPGPComponentSignature> matching = new ArrayList<>();
            for (OpenPGPComponentSignature sig : signatures)
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
            List<OpenPGPComponentSignature> matching = new ArrayList<>();
            for (OpenPGPComponentSignature sig : signatures)
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
            List<OpenPGPComponentSignature> matching = new ArrayList<>();
            outer: for (OpenPGPComponentSignature sig : signatures)
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
            List<OpenPGPComponentSignature> wellformed = new ArrayList<>();
            for (OpenPGPComponentSignature sig : signatures)
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

    private OpenPGPComponentKey getComponentKey(List<KeyIdentifier> keyIdentifiers) {
        // We take a list here, since signatures might contain multiple issuer subpackets annoyingly.
        // issuer is primary key

        if (KeyIdentifier.matches(keyIdentifiers, primaryKey.getKeyIdentifier(), false))
        {
            return primaryKey;
        }

        for (KeyIdentifier subkeyIdentifier : subkeys.keySet())
        {
            if (KeyIdentifier.matches(keyIdentifiers, subkeyIdentifier, false))
            {
                return subkeys.get(subkeyIdentifier);
            }
        }

        return null; // external issuer
    }

    /**
     * Component on an OpenPGP certificate.
     * Components can either be {@link OpenPGPComponentKey keys} or {@link OpenPGPIdentityComponent identities}.
     */
    public static class OpenPGPCertificateComponent
    {
        private final OpenPGPCertificate certificate;

        public OpenPGPCertificateComponent(OpenPGPCertificate certificate)
        {
            this.certificate = certificate;
        }

        public OpenPGPCertificate getCertificate()
        {
            return certificate;
        }
    }

    /**
     * A component key is either a primary key, or a subkey.
     *
     * @see <a href="https://openpgp.dev/book/certificates.html#layers-of-keys-in-openpgp">
     *     OpenPGP for Application Developers - Layers of keys in OpenPGP</a>
     */
    public static class OpenPGPComponentKey
            extends OpenPGPCertificateComponent
    {
        protected final PGPPublicKey rawPubkey;

        public OpenPGPComponentKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(certificate);
            this.rawPubkey = rawPubkey;
        }

        public KeyIdentifier getKeyIdentifier()
        {
            return new KeyIdentifier(rawPubkey);
        }
    }

    /**
     * The primary key of a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPPrimaryKey
            extends OpenPGPComponentKey
    {
        protected final List<OpenPGPIdentityComponent> identityComponents;

        public OpenPGPPrimaryKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
            this.identityComponents = new ArrayList<>();
        }
    }

    /**
     * A subkey on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPSubkey
            extends OpenPGPComponentKey
    {
        public OpenPGPSubkey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
        }
    }

    /**
     * An identity bound to the {@link OpenPGPPrimaryKey} of a {@link OpenPGPCertificate}.
     * An identity may either be a {@link OpenPGPUserId} or (deprecated) {@link OpenPGPUserAttribute}.
     */
    public static class OpenPGPIdentityComponent
            extends OpenPGPCertificateComponent
    {
        private final OpenPGPPrimaryKey primaryKey;

        public OpenPGPIdentityComponent(OpenPGPPrimaryKey primaryKey)
        {
            super(primaryKey.getCertificate());
            this.primaryKey = primaryKey;
        }

        public OpenPGPPrimaryKey getPrimaryKey()
        {
            return primaryKey;
        }
    }

    /**
     * A UserId.
     */
    public static class OpenPGPUserId
            extends OpenPGPIdentityComponent
    {
        private final String userId;

        public OpenPGPUserId(String userId, OpenPGPPrimaryKey primaryKey)
        {
            super(primaryKey);
            this.userId = userId;
        }

        @Override
        public String toString() {
            return userId;
        }
    }

    /**
     * A UserAttribute.
     * Use of UserAttributes is deprecated in RFC9580.
     */
    public static class OpenPGPUserAttribute
            extends OpenPGPIdentityComponent
    {

        private final PGPUserAttributeSubpacketVector userAttribute;

        public OpenPGPUserAttribute(PGPUserAttributeSubpacketVector userAttribute, OpenPGPPrimaryKey primaryKey)
        {
            super(primaryKey);
            this.userAttribute = userAttribute;
        }

        public PGPUserAttributeSubpacketVector getUserAttribute()
        {
            return userAttribute;
        }
    }

    /**
     * An OpenPGP signature.
     */
    public static class OpenPGPSignature
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

        public Date getExpirationTime() {
            return null;
        }

        public boolean isCertification()
        {
            return signature.isCertification();
        }

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

    /**
     * OpenPGP Signature made over some {@link OpenPGPCertificateComponent} on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPComponentSignature
            extends OpenPGPSignature
    {

        private OpenPGPComponentKey issuer;
        private final OpenPGPCertificateComponent target;

        /**
         * Component signature.
         * @param signature signature
         * @param issuer key that issued the signature.
         *              Is nullable (e.g. for 3rd party sigs where the certificate is not available).
         * @param target signed certificate component
         */
        public OpenPGPComponentSignature(PGPSignature signature,
                                         OpenPGPComponentKey issuer,
                                         OpenPGPCertificateComponent target)
        {
            super(signature);
            this.issuer = issuer;
            this.target = target;
        }

        public boolean verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPException
        {
            if (issuer == null)
            {
                // No issuer available
                return false;
            }

            // Direct-Key signature
            if (target == issuer)
            {
                return verifyKeySignature(
                        issuer,
                        issuer,
                        contentVerifierBuilderProvider);
            }

            // Subkey binding signature
            if (target instanceof OpenPGPSubkey)
            {
                return verifyKeySignature(
                        issuer,
                        (OpenPGPSubkey) target,
                        contentVerifierBuilderProvider);
            }

            // User-ID binding
            if (target instanceof OpenPGPUserId)
            {
                return verifyUserIdSignature(
                        issuer,
                        (OpenPGPUserId) target,
                        contentVerifierBuilderProvider);
            }

            // User-Attribute binding
            if (target instanceof OpenPGPUserAttribute)
            {
                return verifyUserAttributeSignature(
                        issuer,
                        (OpenPGPUserAttribute) target,
                        contentVerifierBuilderProvider);
            }

            return false;
        }

        public boolean verifyKeySignature(OpenPGPComponentKey issuer,
                                          OpenPGPComponentKey target,
                                          PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.rawPubkey);
                if (issuer == target)
                {
                    isCorrect = signature.verifyCertification(target.rawPubkey);
                }
                else
                {
                    isCorrect = signature.verifyCertification(issuer.rawPubkey, target.rawPubkey);
                }
                return isCorrect;
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw e;
            }
        }


        public boolean verifyUserIdSignature(OpenPGPComponentKey issuer,
                                             OpenPGPUserId target,
                                             PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.rawPubkey);
                isCorrect = signature.verifyCertification(target.userId, target.getPrimaryKey().rawPubkey);
                return isCorrect;
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw e;
            }
        }

        public boolean verifyUserAttributeSignature(OpenPGPComponentKey issuer,
                                                    OpenPGPUserAttribute target,
                                                    PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPException
        {
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.rawPubkey);
                isCorrect = signature.verifyCertification(target.userAttribute, target.getPrimaryKey().rawPubkey);
                return isCorrect;
            }
            catch (PGPException e)
            {
                this.isCorrect = false;
                throw e;
            }
        }

        public boolean isRevocation()
        {
            return PGPSignature.isRevocation(signature.getSignatureType());
        }
    }

    /**
     * Chain of {@link OpenPGPSignature signatures}.
     * Such a chain originates from a certificates primary key and points towards some certificate component that
     * is bound to the certificate.
     * As for example a subkey can only be bound by a primary key that holds either at least one
     * direct-key self-signature or at least one user-id binding signature, multiple signatures may form
     * a validity chain.
     * An {@link OpenPGPSignatureChain} can either be a certification
     * ({@link #isCertification()}), e.g. it represents a positive binding,
     * or it can be a revocation ({@link #isRevocation()}) which invalidates a positive binding.
     */
    public static class OpenPGPSignatureChain
    {
        private final List<Link> chainLinks = new ArrayList<>();

        public static OpenPGPSignatureChain from(OpenPGPComponentSignature sig,
                                                 OpenPGPComponentKey issuer,
                                                 OpenPGPCertificateComponent targetComponent)
        {
            OpenPGPSignatureChain chain = new OpenPGPSignatureChain();
            if (sig.isRevocation())
            {
                chain.chainLinks.add(new Revocation(sig, issuer, targetComponent));
            }
            else
            {
                chain.chainLinks.add(new Certification(sig, issuer, targetComponent));
            }
            return chain;
        }

        public Link getRoot()
        {
            return chainLinks.get(0);
        }

        public Link getHead()
        {
            return chainLinks.get(chainLinks.size() - 1);
        }

        public boolean isCertification()
        {
            for (Link link : chainLinks)
            {
                if (link instanceof Revocation)
                {
                    return false;
                }
            }
            return true;
        }

        public boolean isRevocation()
        {
            for (Link link : chainLinks)
            {
                if (link instanceof Revocation)
                {
                    return true;
                }
            }
            return false;
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
                    .max(Comparator.comparing(OpenPGPComponentSignature::getCreationTime))
                    .map(OpenPGPComponentSignature::getCreationTime)
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

        public boolean isEffectiveAt(Date evaluationDate)
        {
            Date since = getSince();
            Date until = getUntil();
            return !evaluationDate.before(since) && (until == null || evaluationDate.before(until));
        }

        public boolean isValid(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPException
        {
            for (Link link : chainLinks)
            {
                if (!(link instanceof Certification))
                {
                    return false;
                }

                if (link.signature.isTested)
                {
                    return link.signature.isCorrect;
                }

                if (!link.verify(contentVerifierBuilderProvider))
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * Link in a {@link OpenPGPSignatureChain}.
         */
        public static abstract class Link
        {
            protected final OpenPGPComponentSignature signature;
            protected final OpenPGPComponentKey issuer;
            protected final OpenPGPCertificateComponent target;

            public Link(OpenPGPComponentSignature signature,
                        OpenPGPComponentKey issuer,
                        OpenPGPCertificateComponent target)
            {
                this.signature = signature;
                this.issuer = issuer;
                this.target = target;
            }

            public Date since()
            {
                return signature.getCreationTime();
            }

            public Date until()
            {
                return signature.getExpirationTime();
            }

            public boolean verify(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                    throws PGPException
            {
                return signature.verify(contentVerifierBuilderProvider);
            }
        }

        /**
         * "Positive" signature chain link.
         */
        public static class Certification
                extends Link
        {
            /**
             * Positive certification.
             *
             * @param signature signature
             * @param issuer key that issued the certification.
             *               Is nullable (e.g. for 3rd-party sigs where the cert is not available)
             * @param target signed certificate component
             */
            public Certification(OpenPGPComponentSignature signature,
                                 OpenPGPComponentKey issuer,
                                 OpenPGPCertificateComponent target)
            {
                super(signature, issuer, target);
            }
        }

        /**
         * "Negative" signature chain link.
         */
        public static class Revocation
                extends Link
        {
            /**
             * Revocation.
             *
             * @param signature signature
             * @param issuer key that issued the revocation.
             *               Is nullable (e.g. for 3rd-party sigs where the cert is not available)
             * @param target revoked certification component
             */
            public Revocation(OpenPGPComponentSignature signature,
                              OpenPGPComponentKey issuer,
                              OpenPGPCertificateComponent target)
            {
                super(signature, issuer, target);
            }
        }

        /**
         * "Broken" signature chain link.
         */
        public static class Broken
                extends Link
        {

            /**
             * Broken signature.
             * A signature might be broken due to a number of reasons, e.g. malformed-ness, missing required subpackets,
             * use of illegal algorithms, etc.
             * @param signature broken signature
             * @param issuer issuer (might be null for 3rd-party sigs)
             * @param target signed component
             */
            public Broken(OpenPGPComponentSignature signature,
                          OpenPGPComponentKey issuer,
                          OpenPGPCertificateComponent target)
            {
                super(signature, issuer, target);
            }
        }
    }

    /**
     * Collection of multiple {@link OpenPGPSignatureChain} objects.
     */
    public static class OpenPGPSignatureChains
    {
        private final List<OpenPGPSignatureChain> chains = new ArrayList<>();

        /**
         * Add a single chain to the collection.
         * @param chain chain
         */
        public void add(OpenPGPSignatureChain chain)
        {
            this.chains.add(chain);
        }

        /**
         * Return a positive certification chain for the component for the given evaluationTime.
         * @param evaluationTime time for which validity of the {@link OpenPGPCertificateComponent} is checked.
         * @return positive certification chain or null
         */
        public OpenPGPSignatureChain getCertificationAt(Date evaluationTime)
        {
            for (OpenPGPSignatureChain chain : chains)
            {
                boolean isEffective = chain.isEffectiveAt(evaluationTime);
                boolean isCertification = chain.isCertification();
                if (isEffective && isCertification)
                {
                    return chain;
                }
            }
            return null;
        }

        /**
         * Return a negative certification chain for the component for the given evaluationTime.
         * @param evaluationTime time for which revocation-ness of the {@link OpenPGPCertificateComponent} is checked.
         * @return negative certification chain or null
         */
        public OpenPGPSignatureChain getRevocationAt(Date evaluationTime)
        {
            for (OpenPGPSignatureChain chain : chains)
            {
                if (chain.isEffectiveAt(evaluationTime) && chain.isRevocation())
                {
                    return chain;
                }
            }
            return null;
        }

        /**
         * Returns true if for the given {@link OpenPGPCertificateComponent}, there is a valid, positive
         * {@link OpenPGPSignatureChain} while at the same time there is no valid revoking chain.
         * @param evaluationTime time at which the component is tested
         * @return true if component it validly bound and not revoked at evaluation time
         */
        public boolean isCertifiedAt(Date evaluationTime)
                throws PGPException
        {
            // Is certified AND NOT revoked
            OpenPGPSignatureChain certification = getCertificationAt(evaluationTime);
            OpenPGPSignatureChain revocation = getRevocationAt(evaluationTime);
            if (certification != null && certification.isValid(new BcPGPContentVerifierBuilderProvider()))
            {
                if (revocation == null)
                {
                    return true;
                }
                return !revocation.isValid(new BcPGPContentVerifierBuilderProvider());
            }
            return false;
        }
    }

    /**
     * Lazy data structure that holds a map containing {@link OpenPGPCertificateComponent components} and their
     * {@link OpenPGPSignatureChains}.
     * The idea is, that we can lazily evaluate temporal validity of components by checking required signatures
     * and have the data structure as a cache in order to prevent repeated verification of the same signatures.
     * The {@link LazyTemporalSignatureChainCache} can be handed over when evaluating an {@link OpenPGPCertificate}
     * at a different point in time ({@link #setEvaluationDateFor(PGPSignature)} or {@link #setEvaluationDate(Date)}).
     */
    public static class LazyTemporalSignatureChainCache
    {
        private final PGPContentVerifierBuilderProvider contentVerifierBuilderProvider;
        private final Map<OpenPGPCertificateComponent, OpenPGPSignatureChains> allChains = new HashMap<>();

        public LazyTemporalSignatureChainCache(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider) {
            this.contentVerifierBuilderProvider = contentVerifierBuilderProvider;
        }

        public void cachePrimaryKey(OpenPGPPrimaryKey primaryKey)
        {
            OpenPGPSignatureChains keySignatureChains = new OpenPGPSignatureChains();
            Signatures keySignatures = Signatures.keySignaturesOn(primaryKey);

            // Key Signatures
            for (OpenPGPComponentSignature sig : keySignatures.get())
            {
                OpenPGPSignatureChain chain = OpenPGPSignatureChain.from(sig, primaryKey, primaryKey);
                keySignatureChains.add(chain);
            }
            allChains.put(primaryKey, keySignatureChains);

            // Identities
            for (OpenPGPIdentityComponent identity : primaryKey.identityComponents)
            {
                OpenPGPSignatureChains identityChains = new OpenPGPSignatureChains();
                Signatures bindings;

                if (identity instanceof OpenPGPUserId)
                {
                    bindings = Signatures.userIdSignaturesOn(
                            primaryKey,
                            ((OpenPGPUserId) identity).userId);
                }
                else
                {
                    bindings = Signatures.userAttributeSignaturesOn(
                            primaryKey,
                            ((OpenPGPUserAttribute) identity).userAttribute);
                }

                for (OpenPGPComponentSignature sig : bindings.get())
                {
                    OpenPGPSignatureChain chain = OpenPGPSignatureChain.from(sig, primaryKey, identity);
                    identityChains.add(chain);
                }
                allChains.put(identity, identityChains);
            }
        }

        public void cacheSubkey(OpenPGPSubkey subkey)
        {
            Signatures bindingSignatures = Signatures.keySignaturesOn(subkey);
            OpenPGPSignatureChains subkeyChains = new OpenPGPSignatureChains();

            for (OpenPGPComponentSignature sig : bindingSignatures.get())
            {
                OpenPGPComponentKey issuer = subkey.getCertificate().getComponentKey(sig.signature.getKeyIdentifiers());
                OpenPGPSignatureChain chain = OpenPGPSignatureChain.from(sig, issuer, subkey);
                subkeyChains.add(chain);
            }
            this.allChains.put(subkey, subkeyChains);
        }

        public OpenPGPSignatureChain getSignatureChainFor(OpenPGPCertificateComponent component, Date evaluationDate)
        {
            // Check if there are signatures at all for the component
            OpenPGPSignatureChains chains = this.allChains.get(component);
            if (chains == null)
            {
                return null;
            }

            // If there is a revocation, return it
            OpenPGPSignatureChain revocation = chains.getRevocationAt(evaluationDate);
            if (revocation != null)
            {
                return revocation;
            }

            // else return a certification
            return chains.getCertificationAt(evaluationDate);
        }
    }
}
