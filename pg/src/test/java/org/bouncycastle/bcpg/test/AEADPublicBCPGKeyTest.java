package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADPublicBCPGKey;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class AEADPublicBCPGKeyTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "AEADPublicBCPGKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testFreshAEADPublicKeyEncodingLength();
        testEncodeParseFreshAEADPublicKey();
        testParseKnownTestVector();
        mismatchedSeedLengthFails();
    }

    private void testFreshAEADPublicKeyEncodingLength()
    {
        AEADPublicBCPGKey k = new AEADPublicBCPGKey(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
        isEquals("Symmetric key algorithm ID mismatch",
                SymmetricKeyAlgorithmTags.AES_256, k.getSymmetricKeyAlgorithmId());
        isEquals("AEAD algorithm ID mismatch", AEADAlgorithmTags.OCB, k.getAeadAlgorithmId());
        isTrue("Packet encoding length mismatch", k.getEncoded().length == 34);
    }

    private void testEncodeParseFreshAEADPublicKey()
            throws IOException
    {
        AEADPublicBCPGKey k = new AEADPublicBCPGKey(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
        ByteArrayInputStream bIn = new ByteArrayInputStream(k.getEncoded());
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        AEADPublicBCPGKey parsed = new AEADPublicBCPGKey(pIn);
        isEncodingEqual(k.getEncoded(), parsed.getEncoded());
    }

    private void testParseKnownTestVector()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(
                Hex.decode("070167906b7b1168f64f8b2974361bc3fda805a5564cdcb851129099a3bf7e712d83"));
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        AEADPublicBCPGKey k = new AEADPublicBCPGKey(pIn);

        isEquals("Symmetric Key Algorithm ID mismatch", 0x07, k.getSymmetricKeyAlgorithmId());
        isEquals("AEAD Algorithm ID mismatch", 0x01, k.getAeadAlgorithmId());
        isEncodingEqual("Fingerprint Seed mismatch",
                Hex.decode("67906b7b1168f64f8b2974361bc3fda805a5564cdcb851129099a3bf7e712d83"),
                k.getFingerprintSeed());
    }

    private void mismatchedSeedLengthFails()
    {
        try
        {
            new AEADPublicBCPGKey(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB, new byte[31]);
            fail("Expected IOException for seed lengths other than 32");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new AEADPublicBCPGKeyTest());
    }
}
