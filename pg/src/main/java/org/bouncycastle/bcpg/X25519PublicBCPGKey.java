package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc7748.X25519;

import java.io.IOException;

public class X25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = X25519.POINT_SIZE;

    public X25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X25519PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
