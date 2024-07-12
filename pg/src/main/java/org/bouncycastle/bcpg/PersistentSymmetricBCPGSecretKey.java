package org.bouncycastle.bcpg;

import java.io.IOException;

public abstract class PersistentSymmetricBCPGSecretKey
        extends OctetArrayBCPGKey
{

    PersistentSymmetricBCPGSecretKey(int length, BCPGInputStream in)
            throws IOException
    {
        super(length, in);
        if (in.available() != 0)
        {
            throw new IOException("Excess bytes at the end of persistent symmetric key encountered.");
        }
    }

    PersistentSymmetricBCPGSecretKey(int length, byte[] key)
            throws IOException
    {
        super(length, checkArrayLength(key, length));
    }

    private static byte[] checkArrayLength(byte[] array, int expectedLength)
            throws IOException
    {
        if (array.length != expectedLength)
        {
            throw new IOException("Expected " + expectedLength + " bytes, but got " + array.length);
        }
        return array;
    }
}
