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
import org.pgpainless.cardio.api.OpenPGPCard;
import org.pgpainless.cardio.api.SmartCard;
import org.pgpainless.cardio.openpgp.KeyType;
import org.pgpainless.cardio.openpgp.dataobject.AlgorithmAttributesDO;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

public class CardioOpenPGPSmartCard
        extends OpenPGPSmartCard
{
    private final SmartCard card;

    private final Integer serialNumber;
    private final String version;
    private final SupportedAlgorithms supportedAlgorithms;
    private final Map<Byte, OpenPGPCard.Key> keys;

    public CardioOpenPGPSmartCard(CardioOpenPGPSmartCardBackend backend, SmartCard card)
    {
        super(backend);
        this.card = card;

        try (CardioSession session = open(true))
        {
            serialNumber = session.openpgp.getSerialNumber();
            version = session.openpgp.getVersion();
            keys = session.openpgp.getKeys();
            supportedAlgorithms = session.getSupportedAlgorithms();
        }
    }

    private void readMetadata(CardioSession session)
    {
        keys.clear();
        keys.putAll(session.openpgp.getKeys());
    }

    public CardioSession open(boolean exclusive)
    {
        return new CardioSession(this, exclusive);
    }

    @Override
    public Integer getSerialNumber()
    {
        return serialNumber;
    }

    @Override
    public String getVersion()
    {
        return version;
    }

    @Override
    public SupportedAlgorithms getSupportedAlgorithms()
    {
        return supportedAlgorithms;
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
        List<OpenPGPHardwareKey> list = new ArrayList<>();
        for (OpenPGPCard.Key k : keys.values()) {
            list.add(new OpenPGPHardwareKey(
                    this,
                    k.getKeyRef(),
                    k.getStatus().getCode(),
                    k.getFingerprint(),
                    k.getCreationTime()));
        }
        return list;
    }

    @Override
    public CardioOpenPGPSmartCardBackend getBackend()
    {
        return (CardioOpenPGPSmartCardBackend) super.getBackend();
    }

    @Override
    public String getCardType()
    {
        return "Cardio";
    }

    public static class CardioSession extends Session
    {
        private final OpenPGPCard openpgp;

        protected CardioSession(CardioOpenPGPSmartCard card, boolean exclusive)
        {
            super(card);
            openpgp = card.card.selectOpenPGP(exclusive);
        }

        @Override
        protected CardioOpenPGPSmartCard getCard()
        {
            return (CardioOpenPGPSmartCard) card;
        }

        @Override
        public boolean checkUserPIN(CardPinProvider userPinProvider)
                throws CardException
        {
            return openpgp.checkUserPin(userPinProvider.providePIN(card));
        }

        @Override
        public boolean checkAdminPIN(CardPinProvider adminPinProvider)
                throws CardException
        {
            return openpgp.checkAdminPIN(adminPinProvider.providePIN(card));
        }

        @Override
        public CardioSession changeUserPIN(CardPinProvider oldPinProvider, CardPinProvider newPinProvider)
                throws CardException
        {
            try {
                openpgp.changeUserPIN(
                        oldPinProvider.providePIN(card),
                        newPinProvider.providePIN(card));
            }
            catch (org.pgpainless.cardio.engine.CardException e)
            {
                throw new CardException(e);
            }
            return this;
        }

        @Override
        public CardioSession changeAdminPIN(CardPinProvider oldPinProvider, CardPinProvider newPinProvider)
                throws CardException
        {
            try {
                openpgp.changeAdminPIN(
                        oldPinProvider.providePIN(card),
                        newPinProvider.providePIN(card));
            }
            catch (org.pgpainless.cardio.engine.CardException e)
            {
                throw new CardException(e);
            }
            return this;
        }

        @Override
        public OpenPGPSmartCard reset()
                throws CardException
        {
            openpgp.reset();
            getCard().readMetadata(this);
            return card;
        }

        public SupportedAlgorithms getSupportedAlgorithms()
        {
            List<SupportedAlgorithms.Algorithm> algs = new ArrayList<>();
            for (OpenPGPCard.Key k : openpgp.getKeys().values())
            {
                List<AlgorithmAttributesDO> supportByKey = k.getSupportedAlgorithms();
                for (AlgorithmAttributesDO alg : supportByKey)
                {
                    if (alg.getKeyType() instanceof KeyType.EC)
                    {
                        KeyType.EC kt = (KeyType.EC) alg.getKeyType();
                        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.fromContents(kt.getCurveBytes());
                        algs.add(new SupportedAlgorithms.EC(k.getKeyRef(), alg.getAlgId(), oid));
                    }
                    else if (alg.getKeyType() instanceof KeyType.RSA)
                    {
                        KeyType.RSA kt = (KeyType.RSA) alg.getKeyType();
                        algs.add(new SupportedAlgorithms.RSA(k.getKeyRef(), alg.getAlgId(), kt.getLenN()));
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
        protected CardioSession uploadKey(byte keyRef, OpenPGPKey.OpenPGPPrivateKey key, char[] adminPin)
                throws CardException, PGPException
        {
            OpenPGPCard.Key hardwareKey = openpgp.getKeys().get(keyRef);
            if (hardwareKey == null)
            {
                throw new NoSuchElementException("No key with keyRef " + keyRef);
            }
            PGPKeyPair keyPair = key.getKeyPair();
            PrivateKey privKey = getCard().getBackend().getKeyConverter().getPrivateKey(keyPair.getPrivateKey());
            PublicKey pubKey = getCard().getBackend().getKeyConverter().getPublicKey(keyPair.getPublicKey());

            openpgp.verifyAdminPIN(adminPin);
            hardwareKey.importKey(new KeyPair(pubKey, privKey));
            hardwareKey.setCreationTime(keyPair.getPublicKey().getCreationTime());
            byte[] fingerprint = getCard().getBackend().toStoredFingerprint(keyPair.getPublicKey());
            hardwareKey.setFingerprint(fingerprint);

            getCard().readMetadata(this);

            return this;
        }

        @Override
        protected PGPPublicKey implGenerateKey(SupportedAlgorithms.Algorithm algorithm,
                                               int keyVersion,
                                               int publicKeyAlgorithmTag,
                                               boolean subkey,
                                               CardPinProvider adminPinProvider)
                throws CardException
        {
            openpgp.verifyAdminPIN(adminPinProvider.providePIN(card));
            OpenPGPCard.Key key = openpgp.getKeys().get(algorithm.keyRef);
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
            Date creationTime = new Date((new Date().getTime() / 1000) * 1000);
            PublicKey publicKey = key.generateKey(selected);
            PGPPublicKey pgpPublicKey;
            try
            {
                pgpPublicKey = getCard().getBackend().convertPublicKey(publicKey, keyVersion, algorithm.algorithmId, creationTime, subkey);
            }
            catch (PGPException e)
            {
                throw new CardException("Failed to generate key.", e);
            }

            key.setFingerprint(getCard().getBackend().toStoredFingerprint(pgpPublicKey));
            key.setCreationTime(creationTime);

            getCard().readMetadata(this);

            return pgpPublicKey;
        }

        @Override
        public PGPPublicKey reconstructPGPPublicKey(byte keyRef)
                throws CardException, PGPException
        {
            OpenPGPCard.Key key = openpgp.getKeys().get(keyRef);
            PublicKey publicKey = key.getPublicKey();
            return getCard().getBackend().convertPublicKey(publicKey, key.getFingerprint(), key.getCreationTime());
        }

        @Override
        public byte[] sign(byte[] data,
                           OpenPGPHardwareKey key,
                           OpenPGPKey.OpenPGPSecretKey stubKey,
                           KeyPassphraseProvider userPinProvider)
                throws KeyPassphraseException, CardException
        {
            char[] pin = userPinProvider.getKeyPassword(stubKey);
            openpgp.verifyUserPIN(pin, true);
            return openpgp.sign(data);
        }

        @Override
        public byte[] decrypt(byte[] message,
                              OpenPGPHardwareKey openPGPHardwareKey,
                              OpenPGPKey.OpenPGPSecretKey stubKey,
                              KeyPassphraseProvider userPinProvider)
                throws PGPException, CardException
        {
            char[] pin = userPinProvider.getKeyPassword(stubKey);
            openpgp.verifyUserPIN(pin, false);
            return openpgp.decrypt(message);
        }

        @Override
        public byte[] decrypt(PublicKey publicKey,
                              OpenPGPHardwareKey openPGPHardwareKey,
                              OpenPGPKey.OpenPGPSecretKey stubKey,
                              KeyPassphraseProvider userPinProvider)
                throws PGPException, CardException
        {
            char[] pin = userPinProvider.getKeyPassword(stubKey);
            openpgp.verifyUserPIN(pin, false);
            return openpgp.decrypt(publicKey);
        }

        @Override
        public void close()
        {
            openpgp.close();
        }
    }
}
