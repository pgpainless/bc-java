package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeSet;

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
    private static final SimpleDateFormat utcFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
    private final PGPContentVerifierBuilderProvider contentVerifierBuilderProvider;

    protected final PGPPublicKeyRing rawCert;
    protected final OpenPGPPrimaryKey primaryKey;
    protected final Map<KeyIdentifier, OpenPGPSubkey> subkeys;

    private final Map<OpenPGPCertificateComponent, OpenPGPSignatureChains> componentSignatureChains = new HashMap<>();

    static
    {
        utcFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public OpenPGPCertificate(PGPPublicKeyRing rawCert,
                              PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
    {
        this.contentVerifierBuilderProvider = contentVerifierBuilderProvider;

        this.rawCert = rawCert;

        Iterator<PGPPublicKey> rawKeys = rawCert.getPublicKeys();
        PGPPublicKey rawPrimaryKey = rawKeys.next();
        this.primaryKey = new OpenPGPPrimaryKey(rawPrimaryKey, this);
        cachePrimaryKey(primaryKey);

        this.subkeys = new HashMap<>();
        while (rawKeys.hasNext())
        {
            PGPPublicKey rawSubkey = rawKeys.next();
            OpenPGPSubkey subkey = new OpenPGPSubkey(rawSubkey, this);
            subkeys.put(new KeyIdentifier(rawSubkey), subkey);
            cacheSubkey(subkey);
        }
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
     * Return the {@link PGPPublicKeyRing} that this certificate is based on.
     *
     * @return underlying public key ring
     */
    public PGPPublicKeyRing getRawCertificate()
    {
        return rawCert;
    }

    private void cachePrimaryKey(OpenPGPPrimaryKey primaryKey)
    {
        OpenPGPSignatureChains keySignatureChains = new OpenPGPSignatureChains(primaryKey);
        List<OpenPGPComponentSignature> keySignatures = primaryKey.getKeySignatures();

        // Key Signatures
        for (OpenPGPComponentSignature sig : keySignatures)
        {
            OpenPGPSignatureChain chain = OpenPGPSignatureChain.direct(sig, primaryKey, primaryKey);
            keySignatureChains.add(chain);
        }
        componentSignatureChains.put(primaryKey, keySignatureChains);

        // Identities
        for (OpenPGPIdentityComponent identity : primaryKey.identityComponents)
        {
            OpenPGPSignatureChains identityChains = new OpenPGPSignatureChains(identity);
            List<OpenPGPComponentSignature> bindings;

            if (identity instanceof OpenPGPUserId)
            {
                bindings = primaryKey.getUserIdSignatures(((OpenPGPUserId) identity).userId);
            }
            else
            {
                bindings = primaryKey.getUserAttributeSignatures(((OpenPGPUserAttribute) identity).userAttribute);
            }

            for (OpenPGPComponentSignature sig : bindings)
            {
                OpenPGPSignatureChain chain = OpenPGPSignatureChain.direct(sig, primaryKey, identity);
                identityChains.add(chain);
            }
            componentSignatureChains.put(identity, identityChains);
        }
    }

    private void cacheSubkey(OpenPGPSubkey subkey)
    {
        List<OpenPGPComponentSignature> bindingSignatures = subkey.getKeySignatures();
        OpenPGPSignatureChains subkeyChains = new OpenPGPSignatureChains(subkey);

        for (OpenPGPComponentSignature sig : bindingSignatures)
        {
            OpenPGPComponentKey issuer = subkey.getCertificate().getKeyComponent(sig.signature.getKeyIdentifiers());
            OpenPGPSignatureChains issuerChains = getAllSignatureChainsFor(issuer);
            if (!issuerChains.chains.isEmpty())
            {
                for (OpenPGPSignatureChain issuerChain : issuerChains.chains)
                {
                    subkeyChains.add(issuerChain.plus(sig, subkey));
                }
            }
            else
            {
                subkeyChains.add(new OpenPGPSignatureChain(
                        new OpenPGPSignatureChain.Certification(sig, null, subkey)));
            }
        }
        this.componentSignatureChains.put(subkey, subkeyChains);
    }

    private OpenPGPSignatureChain getSignatureChainFor(OpenPGPCertificateComponent component,
                                                       OpenPGPComponentKey origin,
                                                       Date evaluationDate)
    {
        // Check if there are signatures at all for the component
        OpenPGPSignatureChains chains = this.componentSignatureChains.get(component);
        if (chains == null)
        {
            return null;
        }

        OpenPGPSignatureChains fromOrigin = chains.fromOrigin(origin);
        if (fromOrigin == null)
        {
            return null;
        }

        return fromOrigin.getChainAt(evaluationDate);
    }

    public OpenPGPSignatureChains getAllSignatureChainsFor(OpenPGPCertificateComponent component)
    {
        return componentSignatureChains.get(component);
    }

    public boolean isAuthenticated(OpenPGPCertificateComponent component, Date evaluationTime)
    {
        return isAuthenticatedBy(component, getPrimaryKey(), evaluationTime);
    }

    public boolean isAuthenticatedBy(OpenPGPCertificateComponent component, OpenPGPComponentKey root, Date evaluationTime)
    {
        try
        {
            OpenPGPSignatureChain chain = getSignatureChainFor(component, root, evaluationTime);
            if (chain != null)
            {
                if (chain.isValid(contentVerifierBuilderProvider))
                {
                    return !chain.isRevocation();
                }
            }
            return false;
        }
        catch (PGPException e)
        {
            throw new RuntimeException(e);
        }
    }

    public Map<KeyIdentifier, OpenPGPSubkey> getSubkeys()
    {
        return new HashMap<>(subkeys);
    }

    public List<OpenPGPCertificateComponent> getComponents()
    {
        return new ArrayList<>(componentSignatureChains.keySet());
    }

    public OpenPGPComponentKey getKeyComponent(List<KeyIdentifier> keyIdentifiers)
    {
        // We take a list here, since signatures might contain multiple issuer subpackets annoyingly.
        // issuer is primary key

        if (KeyIdentifier.matches(keyIdentifiers, getPrimaryKey().getKeyIdentifier(), false))
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
    public static abstract class OpenPGPCertificateComponent
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

        public abstract String toDetailString();

        public boolean isAuthenticatedAt(Date evaluationTime)
        {
            return certificate.isAuthenticated(this, evaluationTime);
        }
    }

    /**
     * OpenPGP Signature made over some {@link OpenPGPCertificateComponent} on a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPComponentSignature
            extends OpenPGPSignature
    {

        private final OpenPGPComponentKey issuer;
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

        public OpenPGPComponentKey getIssuer()
        {
            return issuer;
        }

        public OpenPGPCertificateComponent getTarget()
        {
            return target;
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
            System.out.println("Test KeySignature " + Hex.toHexString(signature.getDigestPrefix()));
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
            System.out.println("Test UIDSignature " + Hex.toHexString(signature.getDigestPrefix()));
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.rawPubkey);
                isCorrect = signature.verifyCertification(target.getUserId(), target.getPrimaryKey().rawPubkey);
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
            System.out.println("Test UAttrSignature " + Hex.toHexString(signature.getDigestPrefix()));
            this.isTested = true;
            try
            {
                signature.init(contentVerifierBuilderProvider, issuer.rawPubkey);
                isCorrect = signature.verifyCertification(target.getUserAttribute(), target.getPrimaryKey().rawPubkey);
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

        public OpenPGPComponentKey getAuthenticatedKeyComponent()
        {
            if (target instanceof OpenPGPIdentityComponent)
            {
                // Identity signatures indirectly authenticate the primary key
                return ((OpenPGPIdentityComponent) target).getPrimaryKey();
            }
            if (target instanceof OpenPGPComponentKey)
            {
                // Key signatures authenticate the target key
                return (OpenPGPComponentKey) target;
            }
            throw new IllegalArgumentException("Unknown target type.");
        }

        @Override
        public String toString()
        {
            String issuerInfo = getIssuerDisplay();
            String period = utcFormat.format(getCreationTime()) +
                    (getExpirationTime() == null ? "" : ">" + utcFormat.format(getExpirationTime()));
            String validity = isTested ? (isCorrect ? "✓" : "✗") : "❓";
            return getType() + (signature.isHardRevocation() ? "(hard)" : "") + " " + Hex.toHexString(signature.getDigestPrefix()) +
                    " " + issuerInfo + " -> " + target.toString() + " (" + period + ") " + validity;
        }

        private String getIssuerDisplay()
        {
            if (issuer != null)
            {
                return issuer.toString();
            }

            List<KeyIdentifier> issuerPackets = signature.getKeyIdentifiers();
            if (issuerPackets.isEmpty())
            {
                return "External[unknown]";
            }
            KeyIdentifier identifier = issuerPackets.get(0);
            if (identifier.isWildcard())
            {
                return "Anonymous";
            }
            return "External[" + Long.toHexString(identifier.getKeyId()).toUpperCase() + "]";
        }

        private String getType()
        {
            switch (signature.getSignatureType())
            {
                case PGPSignature.BINARY_DOCUMENT:
                    return "BINARY_DOCUMENT";
                case PGPSignature.CANONICAL_TEXT_DOCUMENT:
                    return "CANONICAL_TEXT_DOCUMENT";
                case PGPSignature.STAND_ALONE:
                    return "STANDALONE";
                case PGPSignature.DEFAULT_CERTIFICATION:
                    return "DEFAULT_CERTIFICATION";
                case PGPSignature.NO_CERTIFICATION:
                    return "NO_CERTIFICATION";
                case PGPSignature.CASUAL_CERTIFICATION:
                    return "CASUAL_CERTIFICATION";
                case PGPSignature.POSITIVE_CERTIFICATION:
                    return "POSITIVE_CERTIFICATION";
                case PGPSignature.SUBKEY_BINDING:
                    return "SUBKEY_BINDING";
                case PGPSignature.PRIMARYKEY_BINDING:
                    return "PRIMARYKEY_BINDING";
                case PGPSignature.DIRECT_KEY:
                    return "DIRECT_KEY";
                case PGPSignature.KEY_REVOCATION:
                    return "KEY_REVOCATION";
                case PGPSignature.SUBKEY_REVOCATION:
                    return "SUBKEY_REVOCATION";
                case PGPSignature.CERTIFICATION_REVOCATION:
                    return "CERTIFICATION_REVOCATION";
                case PGPSignature.TIMESTAMP:
                    return "TIMESTAMP";
                case PGPSignature.THIRD_PARTY_CONFIRMATION:
                    return "THIRD_PARTY_CONFIRMATION";
                default:
                    return "UNKNOWN (" + signature.getSignatureType() + ")";
            }
        }
    }

    /**
     * A component key is either a primary key, or a subkey.
     *
     * @see <a href="https://openpgp.dev/book/certificates.html#layers-of-keys-in-openpgp">
     *     OpenPGP for Application Developers - Layers of keys in OpenPGP</a>
     */
    public static abstract class OpenPGPComponentKey
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

        public Date getCreationTime()
        {
            return rawPubkey.getCreationTime();
        }

        protected List<OpenPGPComponentSignature> getKeySignatures()
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignatures();
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                        .getKeyComponent(sig.getKeyIdentifiers());

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, this));
            }
            return list;
        }
    }

    /**
     * The primary key of a {@link OpenPGPCertificate}.
     */
    public static class OpenPGPPrimaryKey
            extends OpenPGPComponentKey
    {
        @Override
        public String toString()
        {
            return "PrimaryKey[" + Long.toHexString(getKeyIdentifier().getKeyId()).toUpperCase() + "]";
        }

        @Override
        public String toDetailString()
        {
            return "PrimaryKey[" + getKeyIdentifier() + "] (" + utcFormat.format(getCreationTime()) + ")";
        }

        protected final List<OpenPGPIdentityComponent> identityComponents;

        public OpenPGPPrimaryKey(PGPPublicKey rawPubkey, OpenPGPCertificate certificate)
        {
            super(rawPubkey, certificate);
            this.identityComponents = new ArrayList<>();
        }

        public List<OpenPGPComponentSignature> getUserIdSignatures(String userId)
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignaturesForID(userId);
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                        .getKeyComponent(sig.getKeyIdentifiers());

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, this));
            }
            return list;
        }

        public List<OpenPGPComponentSignature> getUserAttributeSignatures(PGPUserAttributeSubpacketVector userAttribute)
        {
            Iterator<PGPSignature> iterator = rawPubkey.getSignaturesForUserAttribute(userAttribute);
            List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
            while (iterator.hasNext())
            {
                PGPSignature sig = iterator.next();
                // try to find issuer for self-signature
                OpenPGPCertificate.OpenPGPComponentKey issuer = getCertificate()
                        .getKeyComponent(sig.getKeyIdentifiers());

                list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, this));
            }
            return list;
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

        @Override
        public String toString()
        {
            return "Subkey[" + Long.toHexString(getKeyIdentifier().getKeyId()).toUpperCase() + "]";
        }

        @Override
        public String toDetailString()
        {
            return "Subkey[" + getKeyIdentifier() + "] (" + utcFormat.format(getCreationTime()) + ")";
        }
    }

    /**
     * An identity bound to the {@link OpenPGPPrimaryKey} of a {@link OpenPGPCertificate}.
     * An identity may either be a {@link OpenPGPUserId} or (deprecated) {@link OpenPGPUserAttribute}.
     */
    public static abstract class OpenPGPIdentityComponent
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

        @Override
        public String toDetailString() {
            return toString();
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

        public String getUserId()
        {
            return userId;
        }

        @Override
        public String toString()
        {
            return "UserID[" + userId + "]";
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

        @Override
        public String toString()
        {
            return "UserAttribute" + userAttribute.toString();
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
            implements Comparable<OpenPGPSignatureChain>
    {
        private final List<Link> chainLinks = new ArrayList<>();

        private OpenPGPSignatureChain(Link rootLink)
        {
            this.chainLinks.add(rootLink);
        }

        // copy constructor
        private OpenPGPSignatureChain(OpenPGPSignatureChain copy)
        {
            this.chainLinks.addAll(copy.chainLinks);
        }

        /**
         * Return an NEW instance of the {@link OpenPGPSignatureChain} with the new link appended.
         * @param sig signature
         * @param targetComponent signature target
         * @return new instance
         */
        public OpenPGPSignatureChain plus(OpenPGPComponentSignature sig,
                                          OpenPGPCertificateComponent targetComponent)
        {
            if (getHeadKey() != sig.getIssuer())
            {
                throw new IllegalArgumentException("Chain head is not equal to link issuer.");
            }

            OpenPGPSignatureChain chain = new OpenPGPSignatureChain(this);

            chain.chainLinks.add(Link.create(sig, sig.getIssuer(), targetComponent));

            return chain;
        }

        public static OpenPGPSignatureChain direct(OpenPGPComponentSignature sig,
                                                   OpenPGPComponentKey issuer,
                                                   OpenPGPCertificateComponent targetComponent)
        {
            return new OpenPGPSignatureChain(Link.create(sig, issuer, targetComponent));
        }

        public Link getRootLink()
        {
            return chainLinks.get(0);
        }

        public OpenPGPComponentKey getRootKey()
        {
            return getRootLink().issuer;
        }

        public Link getHeadLink()
        {
            return chainLinks.get(chainLinks.size() - 1);
        }

        public OpenPGPComponentKey getHeadKey()
        {
            return getHeadLink().signature.getAuthenticatedKeyComponent();
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

        public boolean isHardRevocation()
        {
            for (Link link : chainLinks)
            {
                if (link instanceof Revocation)
                {
                    if (link.signature.signature.isHardRevocation())
                    {
                        return true;
                    }
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
            Date soonestExpiration = null;
            for (Link link : chainLinks)
            {
                Date until = link.until();
                if (until != null)
                {
                    soonestExpiration = (soonestExpiration == null) ? until :
                            (until.before(soonestExpiration) ? until : soonestExpiration);
                }
            }
            return soonestExpiration;
        }

        public boolean isEffectiveAt(Date evaluationDate)
        {
            if (isHardRevocation())
            {
                return true;
            }
            Date since = getSince();
            Date until = getUntil();
            return !evaluationDate.before(since) && (until == null || evaluationDate.before(until));
        }

        public boolean isValid(PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
                throws PGPException
        {
            boolean correct = true;
            for (Link link : chainLinks)
            {
                if (!link.signature.isTested)
                {
                    link.verify(contentVerifierBuilderProvider);
                }

                if (!link.signature.isCorrect)
                {
                    correct = false;
                }
            }
            return correct;
        }

        @Override
        public String toString()
        {
            StringBuilder b = new StringBuilder();
            String until = getUntil() == null ? "EndOfTime" : utcFormat.format(getUntil());
            b.append("From ").append(utcFormat.format(getSince())).append(" until ").append(until).append("\n");
            for (Link link : chainLinks)
            {
                b.append("  ").append(link.toString()).append("\n");
            }
            return b.toString();
        }

        @Override
        public int compareTo(OpenPGPSignatureChain other)
        {
            if (isHardRevocation())
            {
                return -1;
            }

            if (other.isHardRevocation())
            {
                return 1;
            }

            return -getSince().compareTo(other.getSince());
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

            @Override
            public String toString()
            {
                return signature.toString();
            }

            public static Link create(OpenPGPComponentSignature signature,
                                      OpenPGPComponentKey issuer,
                                      OpenPGPCertificateComponent target)
            {
                if (signature.isRevocation())
                {
                    return new Revocation(signature, issuer, target);
                }
                else
                {
                    return new Certification(signature, issuer, target);
                }
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

            @Override
            public Date since()
            {
                if (signature.signature.isHardRevocation())
                {
                    return new Date(0L);
                }
                return super.since();
            }

            @Override
            public Date until()
            {
                if (signature.signature.isHardRevocation())
                {
                    return new Date(Long.MAX_VALUE);
                }
                return super.until();
            }
        }
    }

    /**
     * Collection of multiple {@link OpenPGPSignatureChain} objects.
     */
    public static class OpenPGPSignatureChains
    {
        private final OpenPGPCertificateComponent targetComponent;
        private final Set<OpenPGPSignatureChain> chains = new TreeSet<>();

        public OpenPGPSignatureChains(OpenPGPCertificateComponent component)
        {
            this.targetComponent = component;
        }

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

        public OpenPGPSignatureChains getChainsAt(Date evaluationTime)
        {
            OpenPGPSignatureChains effectiveChains = new OpenPGPSignatureChains(targetComponent);
            for (OpenPGPSignatureChain chain : chains)
            {
                if (chain.isEffectiveAt(evaluationTime))
                {
                    effectiveChains.add(chain);
                }
            }
            return effectiveChains;
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
                if (!chain.isRevocation())
                {
                    continue;
                }

                if (chain.isEffectiveAt(evaluationTime))
                {
                    return chain;
                }
            }
            return null;
        }

        @Override
        public String toString()
        {
            StringBuilder b = new StringBuilder(targetComponent.toDetailString())
                    .append(" is bound with ").append(chains.size()).append(" chains:").append("\n");
            for (OpenPGPSignatureChain chain : chains)
            {
                b.append(chain.toString());
            }
            return b.toString();
        }

        public OpenPGPSignatureChains fromOrigin(OpenPGPComponentKey root)
        {
            OpenPGPSignatureChains chainsFromRoot = new OpenPGPSignatureChains(root);
            for (OpenPGPSignatureChain chain : chains)
            {
                if (chain.getRootKey() == root)
                {
                    chainsFromRoot.add(chain);
                }
            }
            return chainsFromRoot;
        }

        public OpenPGPSignatureChain getChainAt(Date evaluationDate)
        {
            OpenPGPSignatureChains atDate = getChainsAt(evaluationDate);
            Iterator<OpenPGPSignatureChain> it = atDate.chains.iterator();
            if (it.hasNext())
            {
                return it.next();
            }
            return null;
        }
    }
}
