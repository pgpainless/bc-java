package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

/**
 * Collection of signatures on which different filter steps can be applied.
 * Signatures are sorted first by creation time (newest first), then by revocation-hardness.
 * Iterating through the signatures therefore first returns hard revocation signatures,
 * then signatures can be tried newest to oldest.
 */
public class SortedSignatureCollection
{

    // Sort signatures by hard-revocation-ness. Hard revocation are sorted to the front of the list
    private static final Comparator<OpenPGPCertificate.OpenPGPComponentSignature> hardRevocationComparator =
            (one, two) ->
            {
                boolean oneHard = one.signature.isHardRevocation();
                boolean twoHard = two.signature.isHardRevocation();
                return oneHard == twoHard ? 0 : (oneHard ? -1 : 1);
            };

    // descending by creation time (newest first)
    private final List<OpenPGPCertificate.OpenPGPComponentSignature> signatures = new ArrayList<>();

    /**
     * Create a collection of {@link OpenPGPCertificate.OpenPGPComponentSignature certificate signatures}
     * from an unsorted list of {@link PGPSignature PGPSignatures}.
     *
     * @param unsorted unsorted list
     * @return sorted collection
     */
    public static SortedSignatureCollection from(List<OpenPGPCertificate.OpenPGPComponentSignature> unsorted)
    {
        SortedSignatureCollection sigs = new SortedSignatureCollection(unsorted);
        sigs.signatures.sort(Comparator
                .comparing(OpenPGPCertificate.OpenPGPComponentSignature::getCreationTime)
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
    public static SortedSignatureCollection keySignaturesOn(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        Iterator<PGPSignature> iterator = key.rawPubkey.getSignatures();
        List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
        while (iterator.hasNext())
        {
            PGPSignature sig = iterator.next();
            // try to find issuer for self-signature
            OpenPGPCertificate.OpenPGPComponentKey issuer = key.getCertificate()
                    .getComponentKey(sig.getKeyIdentifiers());

            list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, key));
        }
        return SortedSignatureCollection.from(list);
    }

    /**
     * Filter for self-signatures on the given primary key and over the given user id.
     *
     * @param key    primary key
     * @param userId user-id
     * @return self-signatures over the user-id
     */
    public static SortedSignatureCollection userIdSignaturesOn(OpenPGPCertificate.OpenPGPPrimaryKey key,
                                                               String userId)
    {
        Iterator<PGPSignature> iterator = key.rawPubkey.getSignaturesForID(userId);
        List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
        while (iterator.hasNext())
        {
            PGPSignature sig = iterator.next();
            // try to find issuer for self-signature
            OpenPGPCertificate.OpenPGPComponentKey issuer = key.getCertificate()
                    .getComponentKey(sig.getKeyIdentifiers());

            list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, key));
        }
        return SortedSignatureCollection.from(list);
    }

    /**
     * Filter for self-signatures on the given primary key and over the given userAttribute.
     *
     * @param key           primary key
     * @param userAttribute user-attribute
     * @return self-signatures over the user-attribute
     */
    public static SortedSignatureCollection userAttributeSignaturesOn(
            OpenPGPCertificate.OpenPGPPrimaryKey key,
            PGPUserAttributeSubpacketVector userAttribute)
    {
        Iterator<PGPSignature> iterator = key.rawPubkey.getSignaturesForUserAttribute(userAttribute);
        List<OpenPGPCertificate.OpenPGPComponentSignature> list = new ArrayList<>();
        while (iterator.hasNext())
        {
            PGPSignature sig = iterator.next();
            // try to find issuer for self-signature
            OpenPGPCertificate.OpenPGPComponentKey issuer = key.getCertificate()
                    .getComponentKey(sig.getKeyIdentifiers());

            list.add(new OpenPGPCertificate.OpenPGPComponentSignature(sig, issuer, key));
        }
        return SortedSignatureCollection.from(list);
    }

    /**
     * Private constructor.
     * Expects the signatures list to be sorted.
     *
     * @param signatures sorted list
     */
    private SortedSignatureCollection(List<OpenPGPCertificate.OpenPGPComponentSignature> signatures)
    {
        this.signatures.addAll(signatures);
    }

    /**
     * Return all signatures.
     *
     * @return signatures
     */
    public List<OpenPGPCertificate.OpenPGPComponentSignature> get()
    {
        return Collections.unmodifiableList(signatures);
    }

    /**
     * Return the current-most {@link PGPSignature} that matches the criteria.
     *
     * @return signature or null
     */
    public OpenPGPCertificate.OpenPGPComponentSignature current()
    {
        return signatures.isEmpty() ? null : signatures.get(0);
    }
}
