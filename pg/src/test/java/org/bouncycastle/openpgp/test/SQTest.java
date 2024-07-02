package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class SQTest extends SimpleTest {

    public void test() throws IOException, PGPException {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmIA5PducqZ21f5\n" +
                "YQVwrKzMnclNp2qQMk94NIFRydzgQij/XnCVsh2KiZ2KAqAaDzRAzCC44X2zcEYa\n" +
                "hDlDitRJDyIy+WqJnlSw0loCCQIGMUNKfc/Fx6J4968MksBh5w7HmCamhqE6exup\n" +
                "bnHBi/kGB8rz2RGCJpH06zRVBYBl/voL/frzdvttIETbPp+Dwru+exD/MyrWpS6r\n" +
                "PuJNzr6MLp9ukHk=\n" +
                "=Eisa\n" +
                "-----END PGP MESSAGE-----\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing key = (PGPSecretKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
        PGPSecretKey secKey = key.getSecretKey(Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));
        PGPPrivateKey prvKey = secKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decFac = new BcPublicKeyDataDecryptorFactory(prvKey);
        InputStream in = encData.getDataStream(decFac);
    }

    @Override
    public String getName() {
        return "SQTest";
    }

    @Override
    public void performTest() throws Exception {
        test();
    }

    public static void main(String[] args) {
        runTest(new SQTest());
    }
}
