package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.security.PublicKey;

public class EDECPublicKeyFactory
{
    public static PublicKey toPublicKey(AsymmetricKeyParameter peerKey)
    {
        if (peerKey instanceof X25519PublicKeyParameters)
        {
            return new BCXDHPublicKey(peerKey);
        }
        if (peerKey instanceof X448PublicKeyParameters)
        {
            return new BCXDHPublicKey(peerKey);
        }
        if (peerKey instanceof Ed25519PublicKeyParameters)
        {
            return new BCEdDSAPublicKey(peerKey);
        }
        if (peerKey instanceof Ed448PublicKeyParameters)
        {
            return new  BCEdDSAPublicKey(peerKey);
        }
        if (peerKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ecpk = (ECPublicKeyParameters) peerKey;
            if (!(ecpk.getParameters() instanceof ECNamedDomainParameters))
            {
                throw new IllegalArgumentException("Cannot deduce curve parameters");
            }

            ECNamedDomainParameters dParm = (ECNamedDomainParameters) ecpk.getParameters();
            String curveName = ECUtil.getCurveName(dParm.getName());
            ECNamedCurveSpec spec = new ECNamedCurveSpec(
                    curveName,
                    dParm.getCurve(),
                    dParm.getG(),
                    dParm.getN(),
                    dParm.getH(),
                    dParm.getSeed());
            BCECPublicKey pk = new BCECPublicKey("ECDH", ecpk, spec, BouncyCastleProvider.CONFIGURATION);
            return pk;
        }
        throw new IllegalArgumentException("unsupported key type: " + peerKey.getClass().getName());
    }
}
