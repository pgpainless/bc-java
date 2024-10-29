package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
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

public class StaticV6OpenPGPMessageGeneratorTest
        extends AbstractPacketTest
{
    private static final String V6KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
    KeyIdentifier signingKeyIdentifier = new KeyIdentifier(
            Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"));
    KeyIdentifier encryptionKeyIdentifier = new KeyIdentifier(
            Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));

    @Override
    public String getName()
    {
        return "StaticV6OpenPGPMessageGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        staticEncryptedMessage();
        staticSignedMessage();
    }

    private void staticEncryptedMessage()
            throws IOException, PGPException
    {
        PGPSecretKeyRing secretKeys = getTestKey();
        PGPPublicKeyRing certificate = toCert(secretKeys);

        OpenPGPMessageGenerator gen = getStaticGenerator()
                .addEncryptionCertificate(certificate);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream pgOut = (OpenPGPMessageOutputStream) gen.open(bOut);
        pgOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        pgOut.close();

        // System.out.println(bOut);
    }

    private void staticSignedMessage()
            throws IOException, PGPException
    {
        PGPSecretKeyRing secretKeys = getTestKey();
        OpenPGPMessageGenerator gen = getStaticGenerator()
                .addSigningKey(secretKeys, null);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream pgOut = (OpenPGPMessageOutputStream) gen.open(bOut);
        pgOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        pgOut.close();

        System.out.println(bOut);
    }

    /**
     * Return the OpenPGP v6 test key.
     *
     * @return test key
     * @throws IOException if the key cannot be parsed (should not happen)
     */
    private PGPSecretKeyRing getTestKey()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(V6KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(pIn);
        return (PGPSecretKeyRing) objectFactory.nextObject();
    }

    /**
     * Convert a {@link PGPSecretKeyRing} into a {@link PGPPublicKeyRing}.
     * TODO: Replace with dedicated method
     *
     * @param secretKeys secret keys
     * @return public keys
     */
    private PGPPublicKeyRing toCert(PGPSecretKeyRing secretKeys)
    {
        List<PGPPublicKey> pubKeys = new ArrayList<>();
        Iterator<PGPPublicKey> it = secretKeys.getPublicKeys();
        while (it.hasNext())
        {
            pubKeys.add(it.next());
        }
        return new PGPPublicKeyRing(pubKeys);
    }

    /**
     * Return a pre-configured {@link OpenPGPMessageGenerator} which has the complex logic of evaluating
     * recipient keys to determine suitable subkeys, algorithms etc. swapped out for static configuration
     * tailored to the V6 test key.
     *
     * @return static message generator
     */
    public OpenPGPMessageGenerator getStaticGenerator()
    {
        return new OpenPGPMessageGenerator()
                .setEncryptionKeySelector(keyRing -> Collections.singletonList(encryptionKeyIdentifier))
                .setSigningKeySelector(keyRing -> Collections.singletonList(signingKeyIdentifier));
                //.setEncryptionNegotiator(configuration -> OpenPGPMessageGenerator.MessageEncryption.aead(
                //        SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB));
    }

    public static void main(String[] args)
    {
        runTest(new StaticV6OpenPGPMessageGeneratorTest());
    }
}
