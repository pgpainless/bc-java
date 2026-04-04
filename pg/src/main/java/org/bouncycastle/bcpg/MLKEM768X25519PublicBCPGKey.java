package org.bouncycastle.bcpg;

import java.io.IOException;

public class MLKEM768X25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    private static final int LENGTH = X25519PublicBCPGKey.LENGTH + 1184;

    MLKEM768X25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }
}
