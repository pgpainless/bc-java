package org.bouncycastle.bcpg;

import java.io.IOException;

public class MLKEM768X25519SecretBCPGKey
        extends OctetArrayBCPGKey
{
    private static final int LENGTH = X25519SecretBCPGKey.LENGTH + 64;

    public MLKEM768X25519SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }
}
