package org.bouncycastle.openpgp.smartcard.operator.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.api.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.card.CardException;

import java.security.PublicKey;

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
                    throws PGPException
            {
                try
                {
                    return smartcard.getDecryptionKey().decrypt(keyAlgorithm, secretKey, secKeyData[0], userPinProvider);
                }
                catch (CardException e)
                {
                    throw new PGPException("Error decrypting with smart card", e);
                }
            }

            @Override
            public byte[] decrypt(int keyAlgorithm, PublicKey peerKey)
                    throws PGPException
            {
                try
                {
                    return smartcard.getDecryptionKey().decrypt(keyAlgorithm, secretKey, peerKey, userPinProvider);
                }
                catch (CardException e)
                {
                    throw new PGPException("Error decrypting with smart card", e);
                }
            }
        });
    }
}
