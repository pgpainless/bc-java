package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Secret key of type {@link PublicKeyAlgorithmTags#Ed25519}.
 * This type was introduced with RFC9580 and can be used with v4, v6 keys.
 * Note however, that legacy implementations might not understand this key type yet.
 * For a key type compatible with legacy v4 implementations, see {@link EdDSAPublicBCPGKey} with
 * {@link PublicKeyAlgorithmTags#EDDSA_LEGACY}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed2">
 *     OpenPGP - Algorithm-Specific Part for Ed25519 Keys</a>
 */
public class Ed25519SecretBCPGKey
    extends OctetArrayBCPGKey
{
    // 32 octets of the native secret key
    public static final int LENGTH = 32;

    public Ed25519SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed25519SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
