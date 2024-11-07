package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class OpenPGPCertificateTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "OpenPGPCertificateTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        baseCertificateTest();
    }

    private void baseCertificateTest()
            throws IOException
    {
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) objFac.nextObject();

        OpenPGPCertificate certificate = new OpenPGPCertificate(publicKeys, new BcPGPContentVerifierBuilderProvider());
        System.out.println(certificate.isBound(certificate.getPrimaryKey()));
        System.out.println(certificate.isBound(certificate.getSubkeys().values().iterator().next()));
        certificate.getRawCertificate();
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPCertificateTest());
    }
}
