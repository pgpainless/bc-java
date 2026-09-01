package org.bouncycastle.jcajce.provider.asymmetric.ec;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class BCECPublicKeyHelper
{
    public static ECPublicKeyParameters getParameters(BCECPublicKey publicKey)
    {
        return publicKey.engineGetKeyParameters();
    }
}
