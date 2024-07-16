package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

public class PersistentSymmetricKeysTest
        extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "PersistentSymmetricKeysTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        generatePersistentKeyPair();
    }

    private void generatePersistentKeyPair()
            throws IOException, PGPException
    {
        byte[] aes256Key = new byte[32];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(aes256Key);
        Date creationTime = new Date((new Date().getTime() / 1000) * 1000);
        AEADPublicBCPGKey aeadPublicKey = new AEADPublicBCPGKey(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
        AEADSecretBCPGKey aeadSecretKey = new AEADSecretBCPGKey(aes256Key, SymmetricKeyAlgorithmTags.AES_256);
        PGPPublicKey pgpPubKey = new PGPPublicKey(
                new PublicKeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.AEAD, creationTime, aeadPublicKey),
                new BcKeyFingerprintCalculator());
        PGPPrivateKey pgpPrivKey = new PGPPrivateKey(pgpPubKey.getKeyID(), pgpPubKey.getPublicKeyPacket(), aeadSecretKey);
        PGPKeyPair aeadKp = new PGPKeyPair(pgpPubKey, pgpPrivKey);
        PGPSecretKey secKey = new PGPSecretKey(pgpPrivKey, pgpPubKey,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                true, null);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        secKey.encode(pOut);
        pOut.close();
        aOut.close();

        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new PersistentSymmetricKeysTest());
    }
}
