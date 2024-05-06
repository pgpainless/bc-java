package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;

public class Ed25519KeyTest extends AbstractPacketTest {
    @Override
    public String getName() {
        return "Ed25519KeyTest";
    }

    @Override
    public void performTest() throws Exception {
        byte[] key = Hex.decode("c62a0663877fe31b00000020f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        BCPGInputStream in = new BCPGInputStream(new ByteArrayInputStream(key));
        PGPObjectFactory objFactory = new BcPGPObjectFactory(in);
        PGPPublicKeyRing ring = (PGPPublicKeyRing) objFactory.nextObject();
        PGPPublicKey k = ring.getPublicKey();

        isEquals("version mismatch", 6, k.getVersion());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.Ed25519, k.getAlgorithm());
        isEncodingEqual("Fingerprint mismatch", Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"), k.getFingerprint());
    }

    public static void main(String[] args) {
        runTest(new Ed25519KeyTest());
    }
}
