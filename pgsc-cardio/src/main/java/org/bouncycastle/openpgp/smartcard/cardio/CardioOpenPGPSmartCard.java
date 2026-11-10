package org.bouncycastle.openpgp.smartcard.cardio;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.card.SupportedAlgorithms;
import org.bouncycastle.util.Arrays;
import org.pgpainless.cardio.api.OpenPGPCard;
import org.pgpainless.cardio.openpgp.KeyType;
import org.pgpainless.cardio.openpgp.dataobject.AlgorithmAttributesDO;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

public class CardioOpenPGPSmartCard
        extends OpenPGPSmartCard
{
    private final OpenPGPCard card;

    public CardioOpenPGPSmartCard(CardioOpenPGPSmartCardBackend backend, OpenPGPCard card)
    {
        super(backend);
        this.card = card;
    }

    @Override
    public Integer getSerialNumber()
    {
        return card.getSerialNumber();
    }

    @Override
    public String getVersion()
    {
        return card.getVersion();
    }

    @Override
    public SupportedAlgorithms getSupportedAlgorithms()
    {
        List<SupportedAlgorithms.Algorithm> algs = new ArrayList<>();
        for (OpenPGPCard.Key k : card.getKeys().values())
        {
            List<AlgorithmAttributesDO> supportByKey = k.getSupportedAlgorithms();
            for (AlgorithmAttributesDO alg : supportByKey)
            {
                if (alg.getKeyType() instanceof KeyType.EC)
                {
                    KeyType.EC kt = (KeyType.EC) alg.getKeyType();
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.fromContents(kt.getCurveBytes());
                    algs.add(new SupportedAlgorithms.EC(k.getKeyRef(), k.getAlgorithmId(), oid));
                }
                else if (alg.getKeyType() instanceof KeyType.RSA)
                {
                    KeyType.RSA kt = (KeyType.RSA) alg.getKeyType();
                    algs.add(new SupportedAlgorithms.RSA(k.getKeyRef(), k.getAlgorithmId(), kt.getLenN()));
                }
                else
                {
                    // Ignore unknown key type for now
                }
            }
        }
        return new SupportedAlgorithms(algs);
    }

    @Override
    public OpenPGPHardwareKey getKeyByKeyRef(byte keyRef)
    {
        List<OpenPGPHardwareKey> keys = getKeys();
        for (OpenPGPHardwareKey k : keys)
        {
            if (k.getKeyRef() == keyRef)
            {
                return k;
            }
        }
        throw new NoSuchElementException("No key with keyRef " + keyRef);
    }

    @Override
    public List<OpenPGPHardwareKey> getKeys()
    {
        List<OpenPGPHardwareKey> keys = new ArrayList<>();
        for (OpenPGPCard.Key k : card.getKeys().values()) {
            keys.add(new OpenPGPHardwareKey(
                    this,
                    k.getKeyRef(),
                    k.getStatus().getCode(),
                    k.getFingerprint(),
                    k.getCreationTime()));
        }
        return keys;
    }

    @Override
    public boolean checkUserPIN(CardPinProvider userPinProvider)
            throws CardException
    {
        return card.checkUserPin(userPinProvider.providePIN(this));
    }

    @Override
    public boolean checkAdminPIN(CardPinProvider adminPinProvider)
            throws CardException
    {
        return card.checkAdminPIN(adminPinProvider.providePIN(this));
    }

    @Override
    public OpenPGPSmartCard changeUserPIN(CardPinProvider oldPinProvider, CardPinProvider newPinProvider)
            throws CardException
    {
        card.changeUserPIN(
                oldPinProvider.providePIN(this),
                newPinProvider.providePIN(this));
        return this;
    }

    @Override
    public OpenPGPSmartCard changeAdminPIN(CardPinProvider oldPinProvider, CardPinProvider newPinProvider)
            throws CardException
    {
        card.changeAdminPIN(
                oldPinProvider.providePIN(this),
                newPinProvider.providePIN(this));
        return this;
    }

    @Override
    public OpenPGPSmartCard reset()
            throws CardException
    {
        card.reset();
        return this;
    }

    @Override
    protected OpenPGPSmartCard uploadKey(byte keyRef, OpenPGPKey.OpenPGPPrivateKey key, char[] adminPin)
            throws CardException, PGPException
    {
        OpenPGPCard.Key hardwareKey = card.getKeys().get(keyRef);
        if (hardwareKey == null)
        {
            throw new NoSuchElementException("No key with keyRef " + keyRef);
        }
        PGPKeyPair keyPair = key.getKeyPair();
        PrivateKey privKey = getBackend().getKeyConverter().getPrivateKey(keyPair.getPrivateKey());
        PublicKey pubKey = getBackend().getKeyConverter().getPublicKey(keyPair.getPublicKey());

        card.verifyAdminPIN(adminPin);
        hardwareKey.importKey(new KeyPair(pubKey, privKey));
        hardwareKey.setCreationTime(keyPair.getPublicKey().getCreationTime());
        byte[] fingerprint = getBackend().toStoredFingerprint(keyPair.getPublicKey());
        hardwareKey.setFingerprint(fingerprint);

        return this;
    }

    @Override
    public CardioOpenPGPSmartCardBackend getBackend()
    {
        return (CardioOpenPGPSmartCardBackend) super.getBackend();
    }

    @Override
    public PGPPublicKey generateKey(SupportedAlgorithms.Algorithm algorithm,
                                    int keyVersion,
                                    int publicKeyAlgorithmTag,
                                    boolean subkey,
                                    CardPinProvider adminPinProvider)
            throws CardException
    {
        OpenPGPCard.Key key = card.getKeys().get(algorithm.keyRef);
        List<AlgorithmAttributesDO> attrs = key.getSupportedAlgorithms();

        AlgorithmAttributesDO selected = null;
        for (AlgorithmAttributesDO attr : attrs)
        {
            if (attr.getAlgId() != algorithm.algorithmId)
            {
                continue;
            }

            if (attr.getKeyType() instanceof KeyType.RSA && algorithm instanceof SupportedAlgorithms.RSA)
            {
                SupportedAlgorithms.RSA requestRSA = (SupportedAlgorithms.RSA) algorithm;
                KeyType.RSA availRSA = (KeyType.RSA) attr.getKeyType();
                if (requestRSA.keySize == availRSA.getLenN())
                {
                    selected = attr;
                    break;
                }
            }
            else if (attr.getKeyType() instanceof KeyType.EC && algorithm instanceof SupportedAlgorithms.EC)
            {
                SupportedAlgorithms.EC requestEC = (SupportedAlgorithms.EC) algorithm;
                KeyType.EC availEC = (KeyType.EC) attr.getKeyType();
                if (requestEC.curve.equals(ASN1ObjectIdentifier.fromContents(availEC.getCurveBytes())))
                {
                    selected = attr;
                    break;
                }
            }
        }
        if (selected == null)
        {
            throw new CardException("Algorithm not supported.");
        }
        PublicKey publicKey = key.generateKey(selected);

        try
        {
            return getBackend().convertPublicKey(publicKey, keyVersion, algorithm.algorithmId, key.getCreationTime(), subkey);
        }
        catch (PGPException e)
        {
            throw new CardException("Failed to generate key.", e);
        }

    }

    @Override
    public PGPPublicKey reconstructPGPPublicKey(byte keyRef)
            throws CardException, PGPException
    {
        OpenPGPCard.Key key = card.getKeys().get(keyRef);
        PublicKey publicKey = key.getPublicKey();
        return getBackend().convertPublicKey(publicKey, key.getFingerprint(), key.getCreationTime());
    }

    @Override
    public String getCardType()
    {
        return "Cardio";
    }

    @Override
    public byte[] sign(byte[] data,
                       OpenPGPHardwareKey key,
                       OpenPGPKey.OpenPGPSecretKey stubKey,
                       KeyPassphraseProvider userPinProvider)
            throws KeyPassphraseException, CardException
    {
        char[] pin = userPinProvider.getKeyPassword(stubKey);
        card.verifyUserPIN(pin, true);
        Arrays.fill(pin, '0');
        return card.sign(data);
    }

    @Override
    public byte[] decrypt(byte[] message,
                          OpenPGPHardwareKey openPGPHardwareKey,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          KeyPassphraseProvider userPinProvider)
            throws PGPException, CardException
    {
        char[] pin = userPinProvider.getKeyPassword(stubKey);
        card.verifyUserPIN(pin, false);
        Arrays.fill(pin, '0');
        return card.decrypt(message);
    }

    @Override
    public byte[] decrypt(PublicKey publicKey,
                          OpenPGPHardwareKey openPGPHardwareKey,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          KeyPassphraseProvider userPinProvider)
            throws PGPException, CardException
    {
        char[] pin = userPinProvider.getKeyPassword(stubKey);
        card.verifyUserPIN(pin, false);
        Arrays.fill(pin, '0');
        return card.decrypt(publicKey);
    }
}
