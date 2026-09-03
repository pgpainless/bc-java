package org.bouncycastle.openpgp.smartcard.operator.bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.edec.EDECPublicKeyConverter;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.bc.BcExternalPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyCryptoCallback;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.card.CardException;

import java.security.PublicKey;

import static org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey.KEY_REF_DECRYPTION;

/**
 * {@link BcExternalPublicKeyDataDecryptorFactory} routing the private-key operation of OpenPGP session-key
 * recovery to a YubiKey's OpenPGP applet.
 * <p>
 * The card performs the RSA decryption or the ECDH / X25519 agreement; all packet parsing, KDF and key
 * unwrap work stays in {@link org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory}.
 * ElGamal and X448 are not supported by the applet and are rejected.
 */
public class BcSmartCardPublicKeyDataDecryptorFactory<T extends OpenPGPSmartCard>
    extends BcExternalPublicKeyDataDecryptorFactory
{
    private final KeyPassphraseProvider userPinProvider;
    private final T smartcard;

    public BcSmartCardPublicKeyDataDecryptorFactory(OpenPGPKey.OpenPGPSecretKey secretKey,
                                                    T smartcard,
                                                    KeyPassphraseProvider userPinProvider)
        throws PGPException
    {
        super(secretKey);
        this.smartcard = smartcard;
        this.userPinProvider = userPinProvider;
    }

    @Override
    public BcPublicKeyCryptoCallback getExternalKeyCryptoCallback()
    {
        return new BcPublicKeyCryptoCallback()
        {
            @Override
            public byte[] decrypt(int keyAlgorithm, byte[][] pEnc)
            {
                try
                {
                    return smartcard.getDecryptionKey().decrypt(userPinProvider, getSecretKey(), pEnc[0]);
                }
                catch (CardException e)
                {
                    throw new PGPRuntimeOperationException("Error decrypting with smart card", e);
                }
                catch (KeyPassphraseException e)
                {
                    throw new PGPRuntimeOperationException("Wrong smart card PIN provided.", e);
                }
            }

            @Override
            public byte[] decrypt(int keyAlgorithm, AsymmetricKeyParameter peerKey)
                    throws PGPException
            {
                try
                {
                    return smartcard.getDecryptionKey()
                            .decrypt(userPinProvider, getSecretKey(), toPublicKey(keyAlgorithm, peerKey));
                }
                catch (CardException e)
                {
                    throw new PGPRuntimeOperationException("Error decrypting with smart card", e);
                }
                catch (KeyPassphraseException e)
                {
                    throw new PGPRuntimeOperationException("Wrong smart card PIN provided.", e);
                }

            }
        };
    }

    private PublicKey toPublicKey(AsymmetricKeyParameter peerKey)
            throws PGPException
    {
        validateCurveSupport(peerKey);
        return EDECPublicKeyConverter.toPublicKey(peerKey);
    }

    protected void validateCurveSupport(AsymmetricKeyParameter peerKey)
            throws PGPException
    {
        if (peerKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ecpk = (ECPublicKeyParameters) peerKey;
            ECNamedDomainParameters dParm = (ECNamedDomainParameters) ecpk.getParameters();
            if (!smartcard.isCurveSupported(KEY_REF_DECRYPTION, dParm.getName()))
            {
                throw new PGPException("Curve not supported: " + ECUtil.getCurveName(dParm.getName()));
            }
        }
    }
}
