package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class X25519KeyTest extends AbstractPacketTest {

    @Override
    public String getName() {
        return "X25519KeyTest";
    }

    @Override
    public void performTest() throws Exception {
        testParseEd25519PublicKey();
    }

    private void testParseEd25519PublicKey() throws IOException {
        byte[] enc = Hex.decode("c62a0663877fe319000000208693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        ByteArrayInputStream bIn = new ByteArrayInputStream(enc);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFactory = new BcPGPObjectFactory(pIn);
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
