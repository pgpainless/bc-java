package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class OpenPGPMessageGeneratorTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "OpenPGPMessageGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        armoredLiteralDataPacket();
        unarmoredLiteralDataPacket();

        staticSignedAndEncryptedMessage();
    }

    private void armoredLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = (OpenPGPMessageOutputStream) gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEquals(
                "-----BEGIN PGP MESSAGE-----\n" +
                        "\n" +
                        "yxNiAAAAAABIZWxsbywgV29ybGQh\n" +
                        "-----END PGP MESSAGE-----\n",
                bOut.toString());
    }

    private void unarmoredLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setArmored(false); // disable ASCII armor

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = (OpenPGPMessageOutputStream) gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEncodingEqual(Hex.decode("cb1362000000000048656c6c6f2c20576f726c6421"), bOut.toByteArray());
    }

    private void staticSignedAndEncryptedMessage() throws IOException, PGPException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        List<PGPPublicKey> pubKeys = new ArrayList<>();
        Iterator<PGPPublicKey> pIt = secretKeys.getPublicKeys();
        PGPPublicKey primaryKey = pIt.next();
        pubKeys.add(primaryKey);
        KeyIdentifier primaryKeyIdentifier = primaryKey.getKeyIdentifier();
        PGPPublicKey encryptionSubkey = pIt.next();
        pubKeys.add(encryptionSubkey);
        KeyIdentifier encryptionSubkeyIdentifier = encryptionSubkey.getKeyIdentifier();
        PGPPublicKeyRing certificate = new PGPPublicKeyRing(pubKeys);

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();

        // Static implementations of key selection / negotiation logic.
        // In a real world example, you'd rely on better, dynamic solutions.
        // TODO: Implement better solutions as defaults
        OpenPGPMessageGenerator.SubkeySelector signingKeySelector =
                keyRing -> Collections.singletonList(primaryKeyIdentifier);
        OpenPGPMessageGenerator.SubkeySelector encryptionKeySelector =
                keyRing -> Collections.singletonList(encryptionSubkeyIdentifier);
        OpenPGPMessageGenerator.EncryptionNegotiator encryptionNegotiator =
                configuration -> OpenPGPMessageGenerator.MessageEncryption.aead(
                        SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
        gen.setEncryptionKeySelector(encryptionKeySelector);
        gen.setSigningKeySelector(signingKeySelector);
        gen.setEncryptionNegotiator(encryptionNegotiator);

        gen.addEncryptionCertificate(certificate);
        gen.addSigningKey(secretKeys, null);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream pgOut = (OpenPGPMessageOutputStream) gen.open(bOut);
        pgOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        pgOut.close();

        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageGeneratorTest());
    }
}
