package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class X25519KeyTest extends AbstractPacketTest {

    @Override
    public String getName() {
        return "X25519KeyTest";
    }

    @Override
    public void performTest() throws Exception {
        testParseX25519PGPPublicKey();
    }

    private void testParseX25519PGPPublicKey() throws IOException {
        // subkey from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        PGPObjectFactory objFactory = hexObjectFactory("c62a0663877fe319000000208693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        PGPPublicKeyRing ring = (PGPPublicKeyRing) objFactory.nextObject();
        PGPPublicKey key = ring.getPublicKey();

        isEquals("version mismatch", 6, key.getVersion());
        isEquals("algorithm mismatch", PublicKeyAlgorithmTags.X25519, key.getAlgorithm());
        isEncodingEqual("Fingerprint mismatch",
                Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"), key.getFingerprint());
    }

    public static void main(String[] args) {
        runTest(new X25519KeyTest());
    }
}
