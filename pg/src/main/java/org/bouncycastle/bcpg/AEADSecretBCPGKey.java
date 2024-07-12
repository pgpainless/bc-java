package org.bouncycastle.bcpg;

import java.io.IOException;

public class AEADSecretBCPGKey
        extends PersistentSymmetricBCPGSecretKey
{
    public AEADSecretBCPGKey(BCPGInputStream in, int symmetricKeyAlgorithmId)
            throws IOException
    {
        this(lengthFromAlgorithm(symmetricKeyAlgorithmId), in);
    }

    AEADSecretBCPGKey(int length, BCPGInputStream in)
            throws IOException
    {
        super(length, in);
    }

    public AEADSecretBCPGKey(byte[] key, int symmetricKeyAlgorithmId)
            throws IOException
    {
        this(lengthFromAlgorithm(symmetricKeyAlgorithmId), key);
    }

    private static int lengthFromAlgorithm(int symmetricKeyAlgorithm)
        throws IOException
    {
        try
        {
            return SymmetricKeyUtils.getKeyLengthInOctets(symmetricKeyAlgorithm);
        }
        catch (IllegalArgumentException e)
        {
            throw new IOException("Unknown symmetric key algorithm.", e);
        }
    }

    AEADSecretBCPGKey(int length, byte[] key)
            throws IOException
    {
        super(length, key);
    }
}
