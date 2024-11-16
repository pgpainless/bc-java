package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class OpenPGPMessageProcessorTest
        extends AbstractPacketTest
{
    private static final byte[] PLAINTEXT = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
    private static final String v6Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
        return "OpenPGPMessageProcessorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        roundtripUnarmoredPlaintextMessage();
        roundtripArmoredPlaintextMessage();
        roundTripCompressedMessage();
        roundTripCompressedSymEncMessageMessage();
        roundTripV6KeyEncryptedMessage();
    }

    private void roundtripUnarmoredPlaintextMessage()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(false)
                .setCompressionNegotiator(conf -> CompressionAlgorithmTags.UNCOMPRESSED)
                .setIsPadded(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundtripArmoredPlaintextMessage()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .setCompressionNegotiator(conf -> CompressionAlgorithmTags.UNCOMPRESSED)
                .setIsPadded(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripCompressedMessage()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP)
                .setIsPadded(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripCompressedSymEncMessageMessage()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .addEncryptionPassphrase("lal".toCharArray())
                .setEncryptionNegotiator(conf -> OpenPGPMessageGenerator.MessageEncryption.integrityProtected(SymmetricKeyAlgorithmTags.AES_256))
                .setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP)
                .setIsPadded(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.setMessagePassphrase("lal".toCharArray());
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripV6KeyEncryptedMessage()
            throws IOException, PGPException
    {
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(v6Key,
                new BcOpenPGPImplementation());

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .addEncryptionCertificate(key.getPGPPublicKeyRing())
                .setIsPadded(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.setKeySource(subkeyIdentifier -> key);
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageProcessorTest());
    }
}
