package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.HMACSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class HMACSecretBCPGKeyTest
        extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "HMACSecretBCPGKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testParseSHA512Key();
        testParseSHA256Key();
    }

    private void testParseSHA512Key()
            throws IOException
    {
        byte[] hash = Hex.decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        HMACSecretBCPGKey k = new HMACSecretBCPGKey(
                hash, HashAlgorithmTags.SHA512);
        isEncodingEqual("key encoding mismatch", hash, k.getKey());
    }

    private void testParseSHA256Key()
        throws IOException
    {
        byte[] hash = Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        HMACSecretBCPGKey k = new HMACSecretBCPGKey(hash, HashAlgorithmTags.SHA256);
        isEncodingEqual("Key encoding mismatch", hash, k.getKey());
    }

    public static void main(String[] args)
    {
        runTest(new HMACSecretBCPGKeyTest());
    }
}
