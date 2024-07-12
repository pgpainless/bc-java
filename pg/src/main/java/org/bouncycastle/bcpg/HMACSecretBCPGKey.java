package org.bouncycastle.bcpg;

import java.io.IOException;

public class HMACSecretBCPGKey
        extends PersistentSymmetricBCPGSecretKey
{
    public HMACSecretBCPGKey(BCPGInputStream in, int hashAlgorithmId)
            throws IOException
    {
        this(HashUtils.getDigestLength(hashAlgorithmId), in);
    }

    HMACSecretBCPGKey(int length, BCPGInputStream in)
            throws IOException
    {
        super(length, in);
    }

    public HMACSecretBCPGKey(byte[] key, int hashAlgorithmId)
            throws IOException
    {
        this(HashUtils.getDigestLength(hashAlgorithmId), key);
    }

    HMACSecretBCPGKey(int length, byte[] key)
            throws IOException
    {
        super(length, key);
    }
}
