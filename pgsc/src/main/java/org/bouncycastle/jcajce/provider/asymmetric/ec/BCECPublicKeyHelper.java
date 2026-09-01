package org.bouncycastle.jcajce.provider.asymmetric.ec;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class BCECPublicKeyHelper
{
    /**
     * Access to package-visible {@link BCECPublicKey#engineGetKeyParameters()} as a public method.
     *
     * @param publicKey ec public key
     * @return underlying {@link ECPublicKeyParameters}
     */
    public static ECPublicKeyParameters getParameters(BCECPublicKey publicKey)
    {
        return publicKey.engineGetKeyParameters();
    }
}
