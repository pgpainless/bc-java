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
import org.bouncycastle.openpgp.PGPException;

import java.security.PublicKey;

/**
 * Utility class for converting {@link AsymmetricKeyParameter} public keys into {@link PublicKey} public keys.
 * This class is used to work package-visible constructors in the
 * {@link org.bouncycastle.jcajce.provider.asymmetric.edec} package.
 */
public class EDECPublicKeyConverter
{

    /**
     * Convert a lightweight {@link AsymmetricKeyParameter} public key into a
     * JCE {@link PublicKey} public key.
     *
     * @param bcPubKey public key
     * @return JCE public key
     * @throws PGPException if the key cannot be converted
     */
    public static PublicKey toPublicKey(AsymmetricKeyParameter bcPubKey)
            throws PGPException
    {
        if (bcPubKey.isPrivate())
        {
            throw new PGPException("Public key expected.");
        }

        if (bcPubKey instanceof X25519PublicKeyParameters)
        {
            return new BCXDHPublicKey(bcPubKey);
        }
        if (bcPubKey instanceof X448PublicKeyParameters)
        {
            return new BCXDHPublicKey(bcPubKey);
        }
        if (bcPubKey instanceof Ed25519PublicKeyParameters)
        {
            return new BCEdDSAPublicKey(bcPubKey);
        }
        if (bcPubKey instanceof Ed448PublicKeyParameters)
        {
            return new BCEdDSAPublicKey(bcPubKey);
        }
        // ECDSA / ECDH
        if (bcPubKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ecpk = (ECPublicKeyParameters) bcPubKey;
            if (!(ecpk.getParameters() instanceof ECNamedDomainParameters))
            {
                throw new PGPException("Cannot deduce curve parameters");
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
            BCECPublicKey pk = new BCECPublicKey("EC", ecpk, spec, BouncyCastleProvider.CONFIGURATION);
            return pk;
        }
        throw new PGPException("unsupported key type: " + bcPubKey.getClass().getName());
    }
}
