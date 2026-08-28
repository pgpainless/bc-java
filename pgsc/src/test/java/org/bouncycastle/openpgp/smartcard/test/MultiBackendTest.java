package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.util.test.SimpleTest;

public class MultiBackendTest extends SimpleTest
{
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
        OpenPGPImplementation implementation = api.getImplementation();
        OpenPGPSmartCardManager manager = new OpenPGPSmartCardManager();

        OpenPGPKey aliceKey = api.generateKey(4)
                .ed25519x25519Key("Alice <alice@example.org>")
                .build();
        SimulatorOpenPGPSmartCardBackend b1 = new SimulatorOpenPGPSmartCardBackend(implementation);
        SimulatorOpenPGPSmartCard c1 = SimulatorOpenPGPSmartCard.createSimulatedCardFrom(b1, 12345, aliceKey);
        b1.addSmartCard(c1);
        manager.addBackend(b1);

        OpenPGPKey bobKey = api.generateKey(4)
                .ed25519x25519Key("Bob <bob@example.org>")
                .build();
        SimulatorOpenPGPSmartCardBackend b2 = new SimulatorOpenPGPSmartCardBackend(implementation);
        SimulatorOpenPGPSmartCard c2 = SimulatorOpenPGPSmartCard.createSimulatedCardFrom(b2, 98765, bobKey);
        b2.addSmartCard(c2);
        manager.addBackend(b2);
    }

    public static void main(String[] args)
    {
        runTest(new MultiBackendTest());
    }
}
