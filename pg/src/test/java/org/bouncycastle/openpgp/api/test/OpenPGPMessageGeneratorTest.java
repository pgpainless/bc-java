package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

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

        armoredCompressedLiteralDataPacket();
        unarmoredCompressedLiteralDataPacket();

        encryptedMessage();
    }

    private void armoredLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setIsPadded(false);
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
        gen.setIsPadded(false); // disable padding

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = (OpenPGPMessageOutputStream) gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEncodingEqual(Hex.decode("cb1362000000000048656c6c6f2c20576f726c6421"), bOut.toByteArray());
    }

    private void armoredCompressedLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setIsPadded(false);
        gen.setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = (OpenPGPMessageOutputStream) gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEquals("-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "yBUBOy2cxAACHqk5Ofk6CuH5RTkpigA=\n" +
                "-----END PGP MESSAGE-----\n",
                bOut.toString());
    }

    private void unarmoredCompressedLiteralDataPacket()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setArmored(false); // no armor
        gen.setIsPadded(false);
        gen.setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = (OpenPGPMessageOutputStream) gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEncodingEqual(Hex.decode("c815013b2d9cc400021ea93939f93a0ae1f94539298a00"), bOut.toByteArray());
    }

    private void encryptedMessage() throws IOException, PGPException {
        String v6Cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(v6Cert.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) objFac.nextObject();

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(publicKeys);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = gen.open(bOut);
        encOut.write("Hello World!\n".getBytes(StandardCharsets.UTF_8));
        encOut.close();

        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageGeneratorTest());
    }
}
