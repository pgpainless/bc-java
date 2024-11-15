package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class OpenPGPKey
        extends OpenPGPCertificate
{
    private final Map<KeyIdentifier, OpenPGPSecretKey> secretKeys;

    public OpenPGPKey(PGPSecretKeyRing rawKey,
                      PGPContentVerifierBuilderProvider contentVerifierBuilderProvider,
                      PBESecretKeyDecryptorBuilderProvider decryptorBuilderProvider)
    {
        super(rawKey, contentVerifierBuilderProvider);

        this.secretKeys = new HashMap<>();
        for (OpenPGPComponentKey key : getKeys())
        {
            KeyIdentifier identifier = key.getKeyIdentifier();
            PGPSecretKey secretKey = rawKey.getSecretKey(identifier);
            if (secretKey == null)
            {
                continue;
            }

            secretKeys.put(identifier, new OpenPGPSecretKey(key, secretKey, decryptorBuilderProvider));
        }
    }

    public Map<KeyIdentifier, OpenPGPSecretKey> getSecretKeys()
    {
        return new HashMap<>(secretKeys);
    }

    public OpenPGPSecretKey getSecretKey(KeyIdentifier identifier)
    {
        return secretKeys.get(identifier);
    }

    public OpenPGPSecretKey getSecretKey(OpenPGPComponentKey key)
    {
        return getSecretKey(key.getKeyIdentifier());
    }

    @Override
    public PGPSecretKeyRing getPGPKeyRing()
    {
        return (PGPSecretKeyRing) super.getPGPKeyRing();
    }

    @Override
    public String toAsciiArmoredString()
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream.Builder armorBuilder = ArmoredOutputStream.builder()
                .clearHeaders();

        for (String slice : fingerprintComments())
        {
            armorBuilder.addComment(slice);
        }

        for (OpenPGPUserId userId : getPrimaryKey().getUserIDs())
        {
            armorBuilder.addComment(userId.getUserId());
        }

        ArmoredOutputStream aOut = armorBuilder.build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        getPGPKeyRing().encode(pOut);
        pOut.close();
        aOut.close();
        return bOut.toString();
    }

    public static class OpenPGPSecretKey
            extends OpenPGPComponentKey
    {
        private final PGPSecretKey rawSecKey;
        private final OpenPGPComponentKey pubKey;
        private final PBESecretKeyDecryptorBuilderProvider decryptorBuilderProvider;

        /**
         * Constructor.
         *
         * @param pubKey                   corresponding public key component
         * @param secKey                   secret key
         * @param decryptorBuilderProvider for unlocking private keys
         */
        public OpenPGPSecretKey(OpenPGPComponentKey pubKey,
                                PGPSecretKey secKey,
                                PBESecretKeyDecryptorBuilderProvider decryptorBuilderProvider)
        {
            super(pubKey.getPGPPublicKey(), pubKey.getCertificate());
            this.decryptorBuilderProvider = decryptorBuilderProvider;
            this.rawSecKey = secKey;
            this.pubKey = pubKey;
        }

        @Override
        protected OpenPGPCertificateComponent getPublicComponent()
        {
            // return the public key component to properly map this secret key to its public key component when
            //  the public key component is used as key in a map.
            return pubKey;
        }

        @Override
        public String toDetailString()
        {
            return "Private" + pubKey.toDetailString();
        }

        public PGPSecretKey getPGPSecretKey()
        {
            return rawSecKey;
        }

        public OpenPGPComponentKey getPublicKey()
        {
            return pubKey;
        }

        public boolean isLocked()
        {
            return getPGPSecretKey().getS2KUsage() != SecretKeyPacket.USAGE_NONE;
        }

        public PGPPrivateKey unlock(char[] passphrase)
                throws PGPException
        {
            PBESecretKeyDecryptor decryptor = decryptorBuilderProvider.provide()
                    .build(passphrase);
            return getPGPSecretKey().extractPrivateKey(decryptor);
        }
    }
}
