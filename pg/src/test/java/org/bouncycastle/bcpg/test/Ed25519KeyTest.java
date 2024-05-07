package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class Ed25519KeyTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "Ed25519KeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testParseEd25519PGPPublicKey();
    }

    private void testParseEd25519PGPPublicKey()
            throws IOException
    {
        // primary key from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        PGPObjectFactory objFactory = hexObjectFactory(
                "c62a0663877fe31b00000020f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFactory.nextObject();
        PGPPublicKey key = cert.getPublicKey();

        isEquals("version mismatch", 6, key.getVersion());
        isEquals("creation time mismatch",
                Long.valueOf("63877fe3", 16) * 1000, key.getCreationTime().getTime());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.Ed25519, key.getAlgorithm());
        isEncodingEqual("ed25519 public key mismatch",
                Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3"),
                key.getPublicKeyPacket().getKey().getEncoded());
        isEncodingEqual("Fingerprint mismatch",
                Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"), key.getFingerprint());
    }

    public static void main(String[] args)
    {
        runTest(new Ed25519KeyTest());
    }
}
