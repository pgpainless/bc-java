package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageGeneratorTest());
    }
}
