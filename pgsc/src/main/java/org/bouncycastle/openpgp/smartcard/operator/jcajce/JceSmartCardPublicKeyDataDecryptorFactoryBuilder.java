package org.bouncycastle.openpgp.smartcard.operator.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;

import java.security.PublicKey;

import static org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey.KEY_REF_DECRYPTION;

public class JceSmartCardPublicKeyDataDecryptorFactoryBuilder<T extends OpenPGPSmartCard>
        extends JceExternalPublicKeyDataDecryptorFactoryBuilder
{
    private final KeyPassphraseProvider userPinProvider;
    private final T smartcard;

    public JceSmartCardPublicKeyDataDecryptorFactoryBuilder(T smartcard,
                                                            KeyPassphraseProvider userPinProvider)
    {
        this.userPinProvider = userPinProvider;
        this.smartcard = smartcard;
    }

    private static PGPKeyPair unlock(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
    {
        OpenPGPKey.OpenPGPPrivateKey privKey = secretKey.unlock();
        if (privKey == null)
        {
            return new PGPKeyPair(secretKey.getPGPPublicKey(), null);
        }
        return privKey.getKeyPair();
    }

    @Override
    public PublicKeyDataDecryptorFactory build(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
    {
        return build(unlock(secretKey), new PublicKeyCryptoCallback()
        {
            @Override
            public byte[] decrypt(int keyAlgorithm, byte[][] secKeyData)
            {
                return smartcard.decrypt(secKeyData[0], smartcard.getDecryptionKey(), secretKey, userPinProvider);
            }

            @Override
            public byte[] decrypt(int keyAlgorithm, PublicKey peerKey)
                    throws PGPException
            {
                validateCurveSupport(peerKey);
                return smartcard.decrypt(peerKey, smartcard.getDecryptionKey(), secretKey, userPinProvider);
            }
        });
    }

    private void validateCurveSupport(PublicKey peerKey)
            throws PGPException
    {
        if (!smartcard.isKeySupported(KEY_REF_DECRYPTION, peerKey))
        {
            throw new PGPException("Curve not supported: " + peerKey.getAlgorithm());
        }
    }
}
