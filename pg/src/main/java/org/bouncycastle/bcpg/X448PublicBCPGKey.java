package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc7748.X448;

import java.io.IOException;

public class X448PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = X448.POINT_SIZE;

    public X448PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X448PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
