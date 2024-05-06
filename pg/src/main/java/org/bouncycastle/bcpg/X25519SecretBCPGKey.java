package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc7748.X25519;

import java.io.IOException;

public class X25519SecretBCPGKey
    extends OctetArrayBCPGKey
{
    public static final int LENGTH = X25519.POINT_SIZE;

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
