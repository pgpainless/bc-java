package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignatureException;

public class MissingIssuerCertException
        extends PGPSignatureException
{
    public MissingIssuerCertException(String message) {
        super(message);
    }
}
