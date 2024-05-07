package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.SecureRandom;

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
        testGenerateRawEd25519KeyPair();
        testParseEd25519PGPPublicKey();
    }

    private void testGenerateRawEd25519KeyPair() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();

        Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters) pair.getPrivate();
        byte[] privEnc = priv.getEncoded();
        isEquals("Private key length mismatch", Ed25519.SECRET_KEY_SIZE, privEnc.length);

        Ed25519PublicKeyParameters pub = (Ed25519PublicKeyParameters) pair.getPublic();
        byte[] pubEnc = pub.getEncoded();
        isEquals("Public key length mismatch", Ed25519.PUBLIC_KEY_SIZE, pubEnc.length);
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
