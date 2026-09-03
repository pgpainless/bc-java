package org.bouncycastle.openpgp.smartcard.operator.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.card.CardException;

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
                try
                {
                    return smartcard.getDecryptionKey().decrypt(userPinProvider, secretKey, secKeyData[0]);
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
            public byte[] decrypt(int keyAlgorithm, PublicKey peerKey)
                    throws PGPException
            {
                try
                {
                    return smartcard.getDecryptionKey().decrypt(userPinProvider, secretKey, peerKey);
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
