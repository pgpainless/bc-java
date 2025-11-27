package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;

/**
 * Builder for {@link PGPContentSigner} objects.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation to use for the {@link PGPContentSigner}.
 */
public interface PGPContentSignerBuilder
{
    PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey)
        throws PGPException;

    /**
     * Build a {@link PGPContentSigner} without direct access to the software private key.
     * This method is useful for e.g. smartcards or other hardware tokens.
     *
     * @param signatureType signature type
     * @return content signer
     *
     * @throws PGPException if a protocol level exception happens
     */
    PGPContentSigner build(final int signatureType)
        throws PGPException;
}
