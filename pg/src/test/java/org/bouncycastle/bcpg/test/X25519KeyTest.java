package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class X25519KeyTest extends AbstractPacketTest {

    @Override
    public String getName() {
        return "X25519KeyTest";
    }

    @Override
    public void performTest() throws Exception {
        test();
    }

    private void test() throws IOException {

        String KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
                "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
                "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
                "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
                "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
                "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
                "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
                "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
                "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        BCPGInputStream in = armoredInputStream(KEY);
        PGPObjectFactory objFactory = new BcPGPObjectFactory(in);
        PGPPublicKeyRing rin = (PGPPublicKeyRing) objFactory.nextObject();
        PGPPublicKey key = rin.getPublicKey();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, true);
        key.encode(pOut);
        bOut.close();
        isEncodingEqual(new byte[0], bOut.toByteArray());
    }

    public static void main(String[] args) {
        runTest(new X25519KeyTest());
    }
}
