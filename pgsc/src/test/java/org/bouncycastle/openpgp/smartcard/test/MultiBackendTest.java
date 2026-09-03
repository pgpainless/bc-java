package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardUtils;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class MultiBackendTest extends SimpleTest
{
    private OpenPGPSmartCardUtils cardUtils = new OpenPGPSmartCardUtils(new BcOpenPGPImplementation());

    @Override
    public String getName()
    {
        return "MultiBackendTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPApi api = new BcOpenPGPApi();
        OpenPGPSmartCardManager manager = new OpenPGPSmartCardManager();

        OpenPGPKey aliceKey = api.generateKey(4)
                .ed25519x25519Key("Alice <alice@example.org>")
                .build();
        OpenPGPKey aliceExt = cardUtils.toExternalKey(aliceKey);

        SimulatorOpenPGPSmartCardBackend b1 = new SimulatorOpenPGPSmartCardBackend();
        SimulatorOpenPGPSmartCard c1 = SimulatorOpenPGPSmartCard.createSimulatedCardFrom(b1, 12345, aliceKey);
        b1.addSmartCard(c1);
        manager.addBackend(b1);

        OpenPGPKey bobKey = api.generateKey(6)
                .ed25519x25519Key("Bob <bob@example.org>")
                .build();
        OpenPGPKey bobExt = cardUtils.toExternalKey(bobKey);

        SimulatorOpenPGPSmartCardBackend b2 = new SimulatorOpenPGPSmartCardBackend();
        SimulatorOpenPGPSmartCard c2 = SimulatorOpenPGPSmartCard.createSimulatedCardFrom(b2, 98765, bobKey);
        b2.addSmartCard(c2);
        manager.addBackend(b2);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addCustomPGPContentSignerBuilderProviderFactory(manager)
                .addSigningKey(aliceExt)
                .addSigningKey(bobExt)
                .addEncryptionCertificate(aliceExt)
                .addEncryptionCertificate(bobExt)
                .open(bOut);
        mOut.write("Hello, World!".getBytes());
        mOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(aliceExt)
                .addVerificationCertificate(bobExt)
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .addDecryptionKey(aliceExt)
                .addDecryptionKey(bobExt)
                .process(bIn);
        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();
        OpenPGPMessageInputStream.Result result = mIn.getResult();

        isTrue(result.getSignatures().size() == 2);
        for (OpenPGPSignature.OpenPGPDocumentSignature sig : result.getSignatures())
        {
            isTrue(sig.isValid());
        }
    }

    public static void main(String[] args)
    {
        runTest(new MultiBackendTest());
    }
}
