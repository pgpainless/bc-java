package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.io.IOException;

public class Ed25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = Ed25519.PUBLIC_KEY_SIZE;

    public Ed25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed25519PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
