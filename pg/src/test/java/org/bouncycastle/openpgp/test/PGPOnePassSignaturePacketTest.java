package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.SecureRandom;

public class PGPOnePassSignaturePacketTest
    extends AbstractPacketTest
{

    private void testV6OPS()
            throws IOException, PGPException
    {
        byte[] salt = new byte[32];
        byte[] fingerprint = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
        long keyID = FingerprintUtil.keyIdFromV6Fingerprint(fingerprint);

        new SecureRandom().nextBytes(salt);
        OnePassSignaturePacket packet = new OnePassSignaturePacket(
                PGPSignature.CANONICAL_TEXT_DOCUMENT,
                HashAlgorithmTags.SHA512,
                PublicKeyAlgorithmTags.EDDSA_LEGACY,
                salt,
                fingerprint,
                false);

        BCPGInputStream pIn = packetInputStreamFrom(packet);
        PGPOnePassSignature ops = new PGPOnePassSignature(pIn);

        isEncodingEqual("Salt mismatch", salt, ops.getSalt());
        isEncodingEqual("Fingerprint mismatch", fingerprint, ops.getFingerprint());
        isEquals("KeyId mismatch", keyID, ops.getKeyID());
        isEquals("Version mismatch", 6, ops.getVersion());
        isEquals("Signature Type mismatch", PGPSignature.CANONICAL_TEXT_DOCUMENT, ops.getSignatureType());
        isEquals("Hash Algorithm mismatch", HashAlgorithmTags.SHA512, ops.getHashAlgorithm());
        isEquals("Key Algorithm mismatch", PublicKeyAlgorithmTags.EDDSA_LEGACY, ops.getKeyAlgorithm());
    }

    private void testV3OPS()
            throws IOException, PGPException
    {
        OnePassSignaturePacket packet = new OnePassSignaturePacket(
                PGPSignature.BINARY_DOCUMENT, HashAlgorithmTags.SHA256,
                PublicKeyAlgorithmTags.RSA_GENERAL, 1337L, false);

        BCPGInputStream pIn = packetInputStreamFrom(packet);
        PGPOnePassSignature ops = new PGPOnePassSignature(pIn);

        isEquals("Version mismatch", 3, ops.getVersion());
        isEquals("Key ID mismatch", 1337L, ops.getKeyID());
        isEquals("Hash Algorithm mismatch", HashAlgorithmTags.SHA256, ops.getHashAlgorithm());
        isEquals("Key Algorithm mismatch", PublicKeyAlgorithmTags.RSA_GENERAL, ops.getKeyAlgorithm());
        isEquals("Signature Type mismatch", PGPSignature.BINARY_DOCUMENT, ops.getSignatureType());
        isNull("Fingerprint MUST be null", ops.getFingerprint());
        isNull("Salt MUST be null", ops.getSalt());
    }

    @Override
    public String getName()
    {
        return "PGPOnePassSignaturePacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testV6OPS();
        testV3OPS();
    }

    public static void main(String[] args)
    {
        runTest(new PGPOnePassSignaturePacketTest());
    }
}
