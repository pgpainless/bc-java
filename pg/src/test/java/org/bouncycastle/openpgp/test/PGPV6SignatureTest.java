package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class PGPV6SignatureTest
        extends AbstractPacketTest
{

    private static final String ARMORED_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
            "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
            "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
            "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
            "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
            "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
            "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
            "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
            "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String ARMORED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    @Override
    public String getName()
    {
        return "PGPV6SignatureTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        verifyV6DirectKeySignatureTestVector();
        generateAndVerifyV6BinarySignature();
        generateAndVerifyV6InlineSignature();
        generateAndVerifyV6CleartextSignature();
    }

    private void verifyV6DirectKeySignatureTestVector()
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_CERT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFac.nextObject();
        PGPPublicKey primaryKey = cert.getPublicKey(Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"));
        PGPPublicKey subkey = cert.getPublicKey(Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));

        PGPSignature directKeySig = primaryKey.getKeySignatures().next();
        PGPSignature subkeyBinding = subkey.getKeySignatures().next();

        directKeySig.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Direct-Key Signature on the primary key MUST be correct.",
                directKeySig.verifyCertification(primaryKey));

        subkeyBinding.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Subkey-Binding Signature MUST be correct.",
                subkeyBinding.verifyCertification(primaryKey, subkey));
    }

    private void generateAndVerifyV6BinarySignature()
            throws IOException, PGPException {
        String msg = "Hello, World!\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        PGPSecretKey signingSecKey = secretKeys.getSecretKey(); // primary key
        PGPPrivateKey signingPrivKey = signingSecKey.extractPrivateKey(null);
        PGPPublicKey signingPubKey = signingSecKey.getPublicKey();
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(
                        signingPubKey.getAlgorithm(),
                        HashAlgorithmTags.SHA512),
                signingPubKey);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, signingPrivKey);
        sigGen.update(msg.getBytes(StandardCharsets.UTF_8));
        PGPSignature binarySig = sigGen.generate();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        binarySig.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut);

        binarySig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        binarySig.update(msg.getBytes(StandardCharsets.UTF_8));
        isTrue("Detached binary signature MUST be valid.",
                binarySig.verify());
    }

    private void generateAndVerifyV6InlineSignature()
            throws IOException, PGPException
    {
        String msg = "Hello, World!\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        PGPSecretKey signingSecKey = secretKeys.getSecretKey(); // primary key
        PGPPrivateKey signingPrivKey = signingSecKey.extractPrivateKey(null);
        PGPPublicKey signingPubKey = signingSecKey.getPublicKey();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .clearHeaders()
                .enableCRC(false)
                .build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signingPubKey.getAlgorithm(), HashAlgorithmTags.SHA512), signingPubKey);
        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, signingPrivKey);
        sigGen.generateOnePassVersion(true).encode(pOut);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(pOut, PGPLiteralDataGenerator.UTF8, "", PGPLiteralDataGenerator.NOW, new byte[512]);

        litOut.write(msg.getBytes(StandardCharsets.UTF_8));
        litOut.close();

        sigGen.update(msg.getBytes(StandardCharsets.UTF_8));
        sigGen.generate().encode(pOut);

        pOut.close();
        aOut.close();

        System.out.println(bOut);

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 OPS", 1, opsList.size());
        PGPOnePassSignature ops = opsList.get(0);

        ops.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);

        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(lit.getDataStream(), plainOut);
        isEncodingEqual("Content of LiteralData packet MUST match plaintext",
                msg.getBytes(StandardCharsets.UTF_8), plainOut.toByteArray());

        ops.update(plainOut.toByteArray());
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly one signature", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        isTrue("Verifying OPS signature MUST succeed", ops.verify(sig));
    }

    private void generateAndVerifyV6CleartextSignature()
            throws IOException, PGPException
    {
        String msg = "Hello, World!\n";
        String msgS = "Hello, World!";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        PGPSecretKey signingSecKey = secretKeys.getSecretKey(); // primary key
        PGPPrivateKey signingPrivKey = signingSecKey.extractPrivateKey(null);
        PGPPublicKey signingPubKey = signingSecKey.getPublicKey();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .clearHeaders()
                .enableCRC(false)
                .build(bOut);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signingPubKey.getAlgorithm(), HashAlgorithmTags.SHA512),
                signingPubKey);
        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, signingPrivKey);

        aOut.beginClearText();
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        sigGen.update(msgS.getBytes(StandardCharsets.UTF_8));
        aOut.write(msg.getBytes(StandardCharsets.UTF_8));

        aOut.endClearText();
        sigGen.generate().encode(pOut);
        pOut.close();
        aOut.close();

        System.out.println(bOut);

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        aIn = new ArmoredInputStream(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        while (aIn.isClearText())
        {
            int c = aIn.read();
            if (aIn.isClearText())
            {
                plainOut.write(c);
            }
        }
        isEncodingEqual("Plaintext MUST match", msg.getBytes(StandardCharsets.UTF_8), plainOut.toByteArray());
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 signature.", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        sig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        sig.update(msgS.getBytes(StandardCharsets.UTF_8));
        isTrue("Signature MUST verify successfully", sig.verify());
    }

    public static void main(String[] args) {
        runTest(new PGPV6SignatureTest());
    }
}
