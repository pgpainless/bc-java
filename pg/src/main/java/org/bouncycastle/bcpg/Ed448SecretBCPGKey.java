package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc8032.Ed448;

import java.io.IOException;

public class Ed448SecretBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = Ed448.SECRET_KEY_SIZE;

    public Ed448SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed448SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
