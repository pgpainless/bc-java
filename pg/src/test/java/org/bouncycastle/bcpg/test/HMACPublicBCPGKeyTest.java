package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HMACPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class HMACPublicBCPGKeyTest
        extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "HMACPublicBCPGKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testEncodeAndParseFreshKey();
        testParseKnownTestVector();

        testConstructWithTooShortFingerprintSeed();
        testConstructWithTooLongFingerprintSeed();
    }

    private void testEncodeAndParseFreshKey()
            throws IOException
    {
        HMACPublicBCPGKey k = new HMACPublicBCPGKey(HashAlgorithmTags.SHA512);
        isEquals("Hash Algorithm ID mismatch", HashAlgorithmTags.SHA512, k.getHashAlgorithmId());
        ByteArrayInputStream bIn = new ByteArrayInputStream(k.getEncoded());
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        HMACPublicBCPGKey parsed = new HMACPublicBCPGKey(pIn);
        isEquals("Encoding length mismatch", 33, k.getEncoded().length);
        isEncodingEqual("Encoding mismatch", k.getEncoded(), parsed.getEncoded());
    }

    private void testParseKnownTestVector()
            throws IOException
    {
        byte[] hex = Hex.decode("0ac4a0532492a62b0fdd5c7ad2e2385fa3ff0845bf6dbc425db396628897e39930");
        ByteArrayInputStream bIn = new ByteArrayInputStream(hex);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        HMACPublicBCPGKey k = new HMACPublicBCPGKey(pIn);

        isEquals("Hash Algorithm ID mismatch", 0x0a, k.getHashAlgorithmId());
        isEncodingEqual("Fingerprint seed mismatch",
                Hex.decode("c4a0532492a62b0fdd5c7ad2e2385fa3ff0845bf6dbc425db396628897e39930"),
                k.getFingerprintSeed());
    }

    private void testConstructWithTooShortFingerprintSeed()
    {
        try
        {
            new HMACPublicBCPGKey(HashAlgorithmTags.SHA256, new byte[3]);
            fail("Constructing public key with too short fingerprint seed MUST fail");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private void testConstructWithTooLongFingerprintSeed()
    {
        try
        {
            new HMACPublicBCPGKey(HashAlgorithmTags.SHA256, new byte[36]);
            fail("Constructing public key with too long fingerprint seed MUST fail");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new HMACPublicBCPGKeyTest());
    }
}
