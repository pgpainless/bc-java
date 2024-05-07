package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.SecureRandom;

public class X25519KeyTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "X25519KeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testGenerateRawX25519KeyPair();
        testParseX25519PGPPublicKey();
    }

    private void testGenerateRawX25519KeyPair() {
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();

        X25519PrivateKeyParameters priv = (X25519PrivateKeyParameters) pair.getPrivate();
        byte[] privEnc = priv.getEncoded();
        isEquals("Private key length mismatch", X25519PrivateKeyParameters.SECRET_SIZE, privEnc.length);

        X25519PublicKeyParameters pub = (X25519PublicKeyParameters) pair.getPublic();
        byte[] pubEnc = pub.getEncoded();
        isEquals("Public key length mismatch", X25519PublicKeyParameters.KEY_SIZE, pubEnc.length);
    }

    private void testParseX25519PGPPublicKey()
            throws IOException
    {
        // subkey from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        PGPObjectFactory objFactory = hexObjectFactory(
                "c62a0663877fe319000000208693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFactory.nextObject();
        PGPPublicKey key = cert.getPublicKey();

        isEquals("version mismatch", 6, key.getVersion());
        isEquals("creation time mismatch",
                Long.valueOf("63877fe3", 16) * 1000, key.getCreationTime().getTime());
        isEquals("algorithm mismatch", PublicKeyAlgorithmTags.X25519, key.getAlgorithm());
        isEncodingEqual("x25519 key mismatch",
                Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435"),
                key.getPublicKeyPacket().getKey().getEncoded());
        isEncodingEqual("Fingerprint mismatch",
                Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"), key.getFingerprint());
    }

    public static void main(String[] args)
    {
        runTest(new X25519KeyTest());
    }
}
