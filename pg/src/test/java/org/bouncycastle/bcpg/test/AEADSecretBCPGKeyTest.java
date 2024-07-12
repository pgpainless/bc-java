package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.AEADSecretBCPGKey;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class AEADSecretBCPGKeyTest
        extends AbstractPacketTest
{
    @Override
    public String getName() {
        return "AEADSecretBCPGKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        constructKnownTestVector();
        parseKnownTestVectorFromBytes();

        parseTooShortKeyLengthFails();
        constructTooShortKeyLengthFails();
        parseTooLongKeyLengthFails();
        constructTooLongKeyLengthFails();

        parseUnknownSymmetricKeyAlgorithmIdFails();
        constructUnknownSymmetricKeyAlgorithmIdFails();
    }

    private void constructKnownTestVector()
            throws IOException
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5bae065dce8a");
        AEADSecretBCPGKey k = new AEADSecretBCPGKey(key, SymmetricKeyAlgorithmTags.AES_256);
        isEncodingEqual("Secret key material encoding mismatch", key, k.getKey());
        isEncodingEqual("Secret key encoding mismatch", key, k.getEncoded());
    }

    private void parseKnownTestVectorFromBytes()
            throws IOException
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5bae065dce8a");
        ByteArrayInputStream bIn = new ByteArrayInputStream(key);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        AEADSecretBCPGKey k = new AEADSecretBCPGKey(pIn, SymmetricKeyAlgorithmTags.AES_256);
        isEncodingEqual("Secret key material encoding mismatch", key, k.getKey());
        isEncodingEqual("Secret key encoding mismatch", key, k.getEncoded());
    }

    private void parseTooShortKeyLengthFails()
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5b");
        ByteArrayInputStream bIn = new ByteArrayInputStream(key);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        try
        {
            new AEADSecretBCPGKey(pIn, SymmetricKeyAlgorithmTags.AES_256);
            fail("Parsing key with mismatched (too short) key length must fail");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private void constructTooShortKeyLengthFails()
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5b");
        try
        {
            new AEADSecretBCPGKey(key, SymmetricKeyAlgorithmTags.AES_256);
            fail("Constructing key with mismatched (too short) key length must fail");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private void parseTooLongKeyLengthFails()
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5bae065dce8ace8a");
        ByteArrayInputStream bIn = new ByteArrayInputStream(key);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        try
        {
            new AEADSecretBCPGKey(pIn, SymmetricKeyAlgorithmTags.AES_256);
            fail("Parsing key with mismatched (too long) key length must fail");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private void constructTooLongKeyLengthFails()
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5bae065dce8ace8a");
        try
        {
            new AEADSecretBCPGKey(key, SymmetricKeyAlgorithmTags.AES_256);
            fail("Constructing key with mismatched (too long) key length must fail");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private void parseUnknownSymmetricKeyAlgorithmIdFails()
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5bae065dce8a");
        ByteArrayInputStream bIn = new ByteArrayInputStream(key);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        try
        {
            new AEADSecretBCPGKey(pIn, 0xff);
            fail("Expected IOException for unknown symmetric key algorithm");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private void constructUnknownSymmetricKeyAlgorithmIdFails()
    {
        byte[] key = Hex.decode("6209b667f58a61e31412e75ac216ba9ab826071a109835787aaa5bae065dce8a");
        try
        {
            new AEADSecretBCPGKey(key, 0xff);
            fail("Expected IOException for unknown symmetric key algorithm");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new AEADSecretBCPGKeyTest());
    }
}
