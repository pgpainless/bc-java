package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;

import java.util.Date;

/**
 * Bouncy Castle implementation of {@link OpenPGPV6KeyGenerator}.
 */
public class BcOpenPGPV6KeyGenerator
        extends OpenPGPV6KeyGenerator
{

    /**
     * Create a new key generator for OpenPGP v6 keys.
     */
    public BcOpenPGPV6KeyGenerator()
            throws PGPException
    {
        this(DEFAULT_SIGNATURE_HASH_ALGORITHM);
    }

    /**
     * Create a new key generator for OpenPGP v6 keys.
     * The key creation time will be set to {@code creationTime}
     *
     * @param creationTime creation time of the generated OpenPGP key
     */
    public BcOpenPGPV6KeyGenerator(Date creationTime)
            throws PGPException
    {
        this(DEFAULT_SIGNATURE_HASH_ALGORITHM, creationTime);
    }

    /**
     * Create a new key generator for OpenPGP v6 keys.
     * Signatures on the key will be generated using the specified {@code signatureHashAlgorithm}.
     *
     * @param signatureHashAlgorithm ID of the hash algorithm to be used for signature generation
     */
    public BcOpenPGPV6KeyGenerator(int signatureHashAlgorithm)
            throws PGPException
    {
        this(signatureHashAlgorithm, new Date());
    }

    /**
     * Create a new OpenPGP key generator for v6 keys.
     *
     * @param signatureHashAlgorithm ID of the hash algorithm used for signatures on the key
     * @param creationTime           creation time of the key and signatures
     */
    public BcOpenPGPV6KeyGenerator(int signatureHashAlgorithm, Date creationTime)
            throws PGPException
    {
        super(
                new BcOpenPGPImplementation(),
                signatureHashAlgorithm,
                false,
                creationTime);
    }
}
