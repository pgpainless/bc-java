package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyOpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Testing a scenario, where the user provided a smart card for decryption, but the message is encrypted
 * for an unrelated software key.
 */
public class UnrelatedSmartCardMessageDecryptionTest
    extends AbstractOpenPGPSmartCardTest
{

    public UnrelatedSmartCardMessageDecryptionTest(OpenPGPSmartCardManager manager,
                                                   TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPSmartCard card = manager.listSmartCards().get(0);
        // -DM System.out.println
        System.out.println("Run UnrelatedSmartCardMessageDecryptionTest on " + card.getCardType() + " " + card.getVersion() + " (" + card.getBackend().getName() + ")");

        OpenPGPKey cardKey = api.generateKey(4)
                .compositeRSAKey(3072, "Eric Cartman <eric@cart.man>")
                .build();
        keyToCard(cardKey, card);

        OpenPGPCertificate.OpenPGPComponentKey cardDecryptionKey = cardKey.getEncryptionKeys().get(0);
        cardKey = toExternalKey(cardKey, cardDecryptionKey.getKeyIdentifier(), null); // move decryption-key to hardware

        cardKey = api.editKey(cardKey)
                .revokeComponentKey(cardDecryptionKey) // revoke hardware-key
                .addEncryptionSubkey() // add software-key
                .done();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addEncryptionCertificate(cardKey.toCertificate()) // will encrypt for software-key
                .open(bOut);

        byte[] msg = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        mOut.write(msg);
        mOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(cardKey)
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();

        isTrue(Arrays.areEqual(msg, bOut.toByteArray()));
    }

    public static void main(String[] args)
    {
        OpenPGPSmartCardManager m;
        TestProperties p;

        // BCYK
        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();

            // BCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, YubikeyOpenPGPSmartCardBackend.bcImpl()));
            runTest(new UnrelatedSmartCardMessageDecryptionTest(m, p));

            // JCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, YubikeyOpenPGPSmartCardBackend.jceImpl()));
            runTest(new UnrelatedSmartCardMessageDecryptionTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of UnrelatedSmartCardMessageDecryptionTest on Yubikey: " + e.getMessage());
        }

        p = new TestProperties(1312);
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, p.getSerialNumber()));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        runTest(new UnrelatedSmartCardMessageDecryptionTest(m, p));
    }

    @Override
    public String getName()
    {
        return "UnrelatedSmartCardMessageDecryptionTest";
    }
}
