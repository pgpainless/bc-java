package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ShortenedOpenPGPIdentifierForLegacyDevicesTest
        extends SimpleTest
{

    public String getName()
    {
        return "ShortenedOpenPGPIdentifierForLegacyDevicesTest";
    }

    public void performTest()
        throws Exception
    {
        SimulatorOpenPGPSmartCardBackend backend = new SimulatorOpenPGPSmartCardBackend();

        testV4FingerprintIsNotShortened(backend);
        testV6FingerprintShortening(backend);
    }

    private void testV4FingerprintIsNotShortened(OpenPGPSmartCardBackend backend)
    {
        // fingerprint from https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-4-ed25519leg
        byte[] v4Fingerprint = Hex.decode("C959BDBAFA32A2F89A153B678CFDE12197965A9A");
        byte[] shortenedFingerprint = backend.toStoredFingerprint(v4Fingerprint, 4);
        isTrue(Arrays.areEqual(v4Fingerprint, shortenedFingerprint));
        isTrue(backend.fingerprintMatches(shortenedFingerprint, v4Fingerprint));
    }

    private void testV6FingerprintShortening(OpenPGPSmartCardBackend backend)
    {
        // Test the example from https://www.ietf.org/archive/id/draft-hko-openpgp-identifiers-for-legacy-devices-01.html#name-example
        byte[] v6Fingerprint = Hex.decode("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9");
        byte[] shortenedFingerprint = backend.toStoredFingerprint(v6Fingerprint, 6);
        isTrue(Arrays.areEqual(Hex.decode("000000000000000000000006cb186c4f0609a697"), shortenedFingerprint));
        isTrue(backend.fingerprintMatches(shortenedFingerprint, v6Fingerprint));
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new ShortenedOpenPGPIdentifierForLegacyDevicesTest());
    }
}
