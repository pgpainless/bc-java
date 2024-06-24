package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class PGPV6SignatureTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "PGPV6SignatureTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        verifyV6DirectKeySignature();
        verifyV6TextSignature();
    }

    private void verifyV6DirectKeySignature() throws IOException, PGPException {
        String armoredCert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(armoredCert.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFac.nextObject();
        PGPPublicKey primaryKey = cert.getPublicKey(Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"));
        PGPPublicKey subkey = cert.getPublicKey(Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));

        PGPSignature directKeySig = primaryKey.getKeySignatures().next();
        PGPSignature subkeyBinding = subkey.getKeySignatures().next();

        directKeySig.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Direct-Key Signature on the primary key MUST be correct.",
                directKeySig.verifyCertification(primaryKey));

        System.out.println("Verify Subkey sig");

        subkeyBinding.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Subkey-Binding Signature MUST be correct.",
                subkeyBinding.verifyCertification(primaryKey, subkey));
    }

    private void verifyV6TextSignature() {
    }


    public static void main(String[] args) {
        runTest(new PGPV6SignatureTest());
    }
}
