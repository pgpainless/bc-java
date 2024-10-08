package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Secret key of type {@link PublicKeyAlgorithmTags#X25519}.
 * This type was introduced with RFC9580 and can be used with v4, v6 keys.
 * Note however, that legacy implementations might not understand this key type yet.
 * For a key type compatible with legacy v4 implementations, see {@link ECSecretBCPGKey} with
 * {@link PublicKeyAlgorithmTags#ECDH}.
 * Note: Contrary to {@link ECSecretBCPGKey} using {@link PublicKeyAlgorithmTags#ECDH}, which uses big-endian
 * MPI encoding to encode the secret key material, {@link X25519SecretBCPGKey} uses native little-endian encoding.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x">
 *     OpenPGP - Algorithm-Specific Part for X25519 Keys</a>
 */
public class X25519SecretBCPGKey
    extends OctetArrayBCPGKey
{
    // 32 octets of the native secret key
    public static final int LENGTH = 32;

    public X25519SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X25519SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
