package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
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
    private final PGPContentVerifierBuilderProvider contentVerifierBuilderProvider;

    protected final PGPPublicKeyRing rawCert;
    protected final Date evaluationTime;

    protected final OpenPGPPrimaryKey primaryKey;
    protected final Map<KeyIdentifier, OpenPGPSubkey> subkeys = new HashMap<>();

    protected final LazyTemporalSignatureChainCache certificationCache = new LazyTemporalSignatureChainCache();

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
        Signatures signatures = Signatures.keySignaturesOn(pk, contentVerifierBuilderProvider);

        Signatures directKeySelfSigs = signatures
                .ofTypes(PGPSignature.DIRECT_KEY)
                .wellformed()
                .issuedBy(pk)
                .createdAtOrBefore(evaluationTime);
        OpenPGPComponentSignature directKeySelfSignature = findCorrectKeySignature(directKeySelfSigs, pk, pk);

        Signatures keyRevocationSelfSigs = signatures
                .ofTypes(PGPSignature.KEY_REVOCATION)
                .wellformed()
                .issuedBy(pk)
                .createdAtOrBefore(evaluationTime);
        OpenPGPComponentSignature keyRevocationSelfSignature = findCorrectKeySignature(keyRevocationSelfSigs, pk, pk);


        return new OpenPGPPrimaryKey(pk, this);
    }

    private OpenPGPComponentSignature findCorrectKeySignature(Signatures candidates, PGPPublicKey issuer, PGPPublicKey target)
    {
        OpenPGPComponentSignature correctSignature = null;
        for (OpenPGPComponentSignature sig : candidates.get())
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
        return null;
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
            throws PGPException
    {
        // TODO: Sanitize signature creation time
        return new OpenPGPCertificate(rawCert, signature.getCreationTime(), contentVerifierBuilderProvider);
    }

    public OpenPGPCertificate reevaluateAt(Date evaluationTime)
            throws PGPException
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

        public static Signatures from(List<OpenPGPComponentSignature> unsorted)
        {
            Signatures sigs = new Signatures(unsorted);
            sigs.signatures.sort(Comparator
                    .comparing(OpenPGPComponentSignature::getCreationTime)
                    .reversed()
                    .thenComparing(hardRevocationComparator));
            return sigs;
        }

        public static Signatures keySignaturesOn(PGPPublicKey key, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            Iterator<PGPSignature> iterator = key.getSignatures();
            List<OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                list.add(new OpenPGPComponentSignature(iterator.next(), contentVerifierBuilderProvider));
            }
            return Signatures.from(list);
        }

        public static Signatures userIdSignaturesOn(PGPPublicKey key, String userId, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            Iterator<PGPSignature> iterator = key.getSignaturesForID(userId);
            List<OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                list.add(new OpenPGPComponentSignature(iterator.next(), contentVerifierBuilderProvider));
            }
            return Signatures.from(list);
        }

        public static Signatures userAttributeSignaturesOn(PGPPublicKey key, PGPUserAttributeSubpacketVector userAttribute, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            Iterator<PGPSignature> iterator = key.getSignaturesForUserAttribute(userAttribute);
            List<OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                list.add(new OpenPGPComponentSignature(iterator.next(), contentVerifierBuilderProvider));
            }
            return Signatures.from(list);
        }

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

    public static class OpenPGPCertificateComponent
    {

    }

    /**
     * A component key is either a primary key, or a subkey.
     *
     * @see <a href="https://openpgp.dev/book/certificates.html#layers-of-keys-in-openpgp">
     *     OpenPGP for Application Developers - Layers of keys in OpenPGP</a>
     */
    public static class OpenPGPComponentKey extends OpenPGPCertificateComponent
    {
        protected final PGPPublicKey rawPubkey;
        protected final OpenPGPCertificate certificate;

        public OpenPGPComponentKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            this.rawPubkey = rawPubkey;
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

        public OpenPGPPrimaryKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
        }
    }

    public static class OpenPGPSubkey extends OpenPGPComponentKey
    {
        public OpenPGPSubkey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
        }

        public OpenPGPPrimaryKey getPrimaryKey()
        {
            return certificate.getPrimaryKey();
        }
    }

    public static class OpenPGPIdentityComponent extends OpenPGPCertificateComponent
    {
        private final OpenPGPPrimaryKey primaryKey;

        public OpenPGPIdentityComponent(OpenPGPPrimaryKey primaryKey)
        {
            this.primaryKey = primaryKey;
        }

        public OpenPGPPrimaryKey getPrimaryKey()
        {
            return primaryKey;
        }
    }

    public static class OpenPGPUserId extends OpenPGPIdentityComponent
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

    public static class OpenPGPUserAttribute extends OpenPGPIdentityComponent
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

    public static class OpenPGPSignature
    {
        protected final PGPContentVerifierBuilderProvider contentVerifierBuilderProvider;
        protected final PGPSignature signature;
        protected boolean isTested = false;
        protected boolean isCorrect = false;

        public OpenPGPSignature(PGPSignature signature,
                                PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            this.signature = signature;
            this.contentVerifierBuilderProvider = contentVerifierBuilderProvider;
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

    public static class OpenPGPDataSignature
            extends OpenPGPSignature
    {

        public OpenPGPDataSignature(PGPSignature signature,
                                    PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            super(signature, contentVerifierBuilderProvider);
        }
    }

    /**
     * OpenPGP Signature made over some {@link OpenPGPCertificateComponent}.
     */
    public static class OpenPGPComponentSignature
            extends OpenPGPSignature
    {

        public OpenPGPComponentSignature(PGPSignature signature, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            super(signature, contentVerifierBuilderProvider);
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
    }

    public static class OpenPGPSignatureChain
    {
        private final List<Link> chainLinks = new ArrayList<>();

        public static OpenPGPSignatureChain from(OpenPGPComponentSignature sig,
                                                 OpenPGPComponentKey issuer,
                                                 OpenPGPCertificateComponent targetComponent)
        {
            OpenPGPSignatureChain chain = new OpenPGPSignatureChain();
            if (sig.isCertification())
            {
                chain.chainLinks.add(new Certification(sig, issuer, targetComponent));
            }
            else
            {
                chain.chainLinks.add(new Revocation(sig, issuer, targetComponent));
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
            return !evaluationDate.before(getSince()) &&
                    evaluationDate.before(getUntil());
        }

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
        }

        /**
         * "Positive" signature chain link.
         */
        public static class Certification
                extends Link
        {
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
            public Revocation(OpenPGPComponentSignature signature,
                              OpenPGPComponentKey issuer,
                              OpenPGPCertificateComponent target)
            {
                super(signature, issuer, target);
            }
        }
    }

    public static class OpenPGPSignatureChains
    {
        private final List<OpenPGPSignatureChain> chains = new ArrayList<>();

        public void add(OpenPGPSignatureChain chain)
        {
            this.chains.add(chain);
        }

        public OpenPGPSignatureChain getCertificationAt(Date evaluationTime)
        {
            for (OpenPGPSignatureChain chain : chains)
            {
                if (chain.isEffectiveAt(evaluationTime) && chain.isCertification())
                {
                    return chain;
                }
            }
            return null;
        }

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

        public boolean isCertifiedAt(Date evaluationTime)
        {
            // Is certified AND NOT revoked
            return getCertificationAt(evaluationTime) != null &&
                    getRevocationAt(evaluationTime) == null;
        }
    }

    public static class LazyTemporalSignatureChainCache
    {
        private final Map<OpenPGPCertificateComponent, OpenPGPSignatureChains> boundComponents = new HashMap<>();

        public void feedPrimaryKey(OpenPGPPrimaryKey primaryKey,
                                   PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            PGPPublicKey pubkey = primaryKey.rawPubkey;
            OpenPGPSignatureChains keySignatureChains = new OpenPGPSignatureChains();
            Signatures keySignatures = Signatures.keySignaturesOn(pubkey, contentVerifierBuilderProvider);

            // Key Signatures
            for (OpenPGPComponentSignature sig : keySignatures.get())
            {
                OpenPGPSignatureChain chain = OpenPGPSignatureChain.from(sig, primaryKey, primaryKey);
                keySignatureChains.add(chain);
            }
            boundComponents.put(primaryKey, keySignatureChains);

            // Identities
            for (OpenPGPIdentityComponent identity : primaryKey.identityComponents)
            {
                OpenPGPSignatureChains identityChains = new OpenPGPSignatureChains();
                Signatures bindings;

                if (identity instanceof OpenPGPUserId)
                {
                    bindings = Signatures.userIdSignaturesOn(
                            pubkey,
                            ((OpenPGPUserId) identity).userId,
                            contentVerifierBuilderProvider);
                }
                else
                {
                    bindings = Signatures.userAttributeSignaturesOn(
                            pubkey,
                            ((OpenPGPUserAttribute) identity).userAttribute,
                            contentVerifierBuilderProvider);
                }

                for (OpenPGPComponentSignature sig : bindings.get())
                {
                    OpenPGPSignatureChain chain = OpenPGPSignatureChain.from(sig, primaryKey, identity);
                    identityChains.add(chain);
                }
                boundComponents.put(identity, identityChains);
            }
        }

        public void feedSubkey(OpenPGPSubkey subkey, PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
        {
            PGPPublicKey pubkey = subkey.rawPubkey;
            OpenPGPSignatureChains chains = new OpenPGPSignatureChains();
            Signatures bindingSignatures = Signatures.keySignaturesOn(pubkey, contentVerifierBuilderProvider);

        }

        public OpenPGPSignatureChain getSignatureChainFor(OpenPGPCertificateComponent component, Date evaluationDate)
        {
            // Check if there are signatures at all for the component
            OpenPGPSignatureChains chains = boundComponents.get(component);
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
