package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignatureException;

public class MalformedPGPSignatureException
        extends PGPSignatureException
{

    public MalformedPGPSignatureException(String message)
    {
        super(message);
    }
}
