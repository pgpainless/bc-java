package org.bouncycastle.openpgp.smartcard.yubikey.operator.bc;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.edec.EDECPublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.bc.BcExternalPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyCryptoCallback;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyOpenPGPSmartCard;

import java.security.PublicKey;

/**
 * {@link BcExternalPublicKeyDataDecryptorFactory} routing the private-key operation of OpenPGP session-key
 * recovery to a YubiKey's OpenPGP applet.
 * <p>
 * The card performs the RSA decryption or the ECDH / X25519 agreement; all packet parsing, KDF and key
 * unwrap work stays in {@link org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory}.
 * ElGamal and X448 are not supported by the applet and are rejected.
 */
public class BcYubikeyPublicKeyDataDecryptorFactory
    extends BcExternalPublicKeyDataDecryptorFactory
{
    private final KeyPassphraseProvider userPinProvider;
    private final YubikeyOpenPGPSmartCard yubikey;

    public BcYubikeyPublicKeyDataDecryptorFactory(OpenPGPKey.OpenPGPSecretKey secretKey,
                                                YubikeyOpenPGPSmartCard yubikey,
                                                KeyPassphraseProvider userPinProvider)
        throws PGPException
    {
        super(secretKey);
        this.yubikey = yubikey;
        this.userPinProvider = userPinProvider;
    }

    @Override
    public BcPublicKeyCryptoCallback getExternalKeyCryptoCallback()
    {
        return new BcPublicKeyCryptoCallback()
        {
            @Override
            public byte[] decrypt(int keyAlgorithm, byte[][] pEnc)
                    throws PGPException, InvalidCipherTextException
            {
                return yubikey.decrypt(pEnc[0], yubikey.getDecryptionKey(), getSecretKey(), userPinProvider);
            }

            @Override
            public byte[] decrypt(int keyAlgorithm, AsymmetricKeyParameter peerKey)
                    throws PGPException, InvalidCipherTextException
            {
                return yubikey.decrypt(toPublicKey(peerKey), yubikey.getDecryptionKey(), getSecretKey(), userPinProvider);
            }
        };
    }

    private PublicKey toPublicKey(AsymmetricKeyParameter peerKey)
            throws PGPException
    {
        validateCurveSupport(peerKey);
        return EDECPublicKeyFactory.toPublicKey(peerKey);
    }

    private static void validateCurveSupport(AsymmetricKeyParameter peerKey)
            throws PGPException
    {
        if (peerKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ecpk = (ECPublicKeyParameters) peerKey;
            ECNamedDomainParameters dParm = (ECNamedDomainParameters) ecpk.getParameters();
            String curveName = ECUtil.getCurveName(dParm.getName());
            if (!isSupportedCurve(curveName))
            {
                throw new PGPException("Curve not supported: " + curveName);
            }
        }
    }

    private static boolean isSupportedCurve(String curveName)
    {
        return "secp256r1".equals(curveName)
            || "prime256v1".equals(curveName)
            || "secp256k1".equals(curveName)
            || "secp384r1".equals(curveName)
            || "secp521r1".equals(curveName)
            || "brainpoolP256r1".equals(curveName)
            || "brainpoolP384r1".equals(curveName)
            || "brainpoolP512r1".equals(curveName)
            || "curve25519".equals(curveName);
    }
}
