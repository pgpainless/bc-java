package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class PersistentSymmetricKeysTest
        extends AbstractPgpKeyPairTest
{

    // https://datatracker.ietf.org/doc/html/draft-bre-openpgp-samples-00#section-2.2
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Alice's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
            "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
            "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
            "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
            "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
            "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
            "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
            "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
            "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
            "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
            "Pnn+We1aTBhaGa86AQ==\n" +
            "=n8OM\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

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
        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        Date creationTime = secretKeys.getPublicKey().getCreationTime();
        byte[] aes256Key = new byte[32];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(aes256Key);
        AEADPublicBCPGKey aeadPublicKey = new AEADPublicBCPGKey(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
        AEADSecretBCPGKey aeadSecretKey = new AEADSecretBCPGKey(aes256Key, SymmetricKeyAlgorithmTags.AES_256);
        PGPPublicKey pgpPubKey = new PGPPublicKey(
                new PublicKeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.AEAD, creationTime, aeadPublicKey),
                new BcKeyFingerprintCalculator());
        PGPPrivateKey pgpPrivKey = new PGPPrivateKey(pgpPubKey.getKeyID(), pgpPubKey.getPublicKeyPacket(), aeadSecretKey);

        PGPPublicKey primaryKey = secretKeys.getPublicKey();
        PGPPrivateKey primaryPrivKey = secretKeys.getSecretKey().extractPrivateKey(null);
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
                secretKeys.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512));
        List<SignatureSubpacket> subpackets = new ArrayList<>();
        subpackets.add(new IssuerFingerprint(false, primaryKey.getVersion(), primaryKey.getFingerprint()));
        subpackets.add(new SignatureCreationTime(false, creationTime));
        subpackets.add(new Features(false, Features.FEATURE_SEIPD_V2));
        subpackets.add(new KeyFlags(true, KeyFlags.ENCRYPT_STORAGE));
        sigGen.setHashedSubpackets(
                PGPSignatureSubpacketVector.fromSubpackets(subpackets.toArray(new SignatureSubpacket[0])));
        sigGen.init(PGPSignature.SUBKEY_BINDING, primaryPrivKey);
        PGPSignature subkeyBinding = sigGen.generateCertification(primaryKey, pgpPubKey);

        pgpPubKey = PGPPublicKey.addCertification(pgpPubKey, subkeyBinding);
        PGPSecretKey persistentSymKey = new PGPSecretKey(pgpPrivKey, pgpPubKey,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                false, null);
        secretKeys = PGPSecretKeyRing.insertSecretKey(secretKeys, persistentSymKey);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();

        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new PersistentSymmetricKeysTest());
    }
}
