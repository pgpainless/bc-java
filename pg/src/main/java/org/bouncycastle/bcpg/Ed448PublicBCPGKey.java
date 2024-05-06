package org.bouncycastle.bcpg;

import org.bouncycastle.math.ec.rfc8032.Ed448;

import java.io.IOException;

public class Ed448PublicBCPGKey
    extends OctetArrayBCPGKey
{
    public static final int LENGTH = Ed448.PUBLIC_KEY_SIZE;

    public Ed448PublicBCPGKey(BCPGInputStream in)
        throws IOException
    {
        super(LENGTH, in);
    }

    public Ed448PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }

}
