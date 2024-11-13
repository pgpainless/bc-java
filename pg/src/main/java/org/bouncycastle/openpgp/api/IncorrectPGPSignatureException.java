package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignatureException;

public class IncorrectPGPSignatureException
        extends PGPSignatureException
{
    public IncorrectPGPSignatureException(String message) {
        super(message);
    }
}
