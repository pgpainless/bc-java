package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.io.IOException;

public class Ed25519SecretBCPGKey
    extends OctetArrayBCPGKey
{
    public static final int LENGTH = Ed25519.SECRET_KEY_SIZE;

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
