package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeySmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
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
        OpenPGPSmartCardManager manager = new OpenPGPSmartCardManager();

        YubikeySmartCardBackend ykBackend = YubikeySmartCardBackend.createInstance();
        ykBackend.addAllowedCardSerial(15472425);
        manager.addBackend(ykBackend);

        SimulatorSmartCardBackend simBackend = new SimulatorSmartCardBackend();
        SimulatorOpenPGPSmartCard simCard = new SimulatorOpenPGPSmartCard(simBackend, 1234);
        simBackend.addSmartCard(simCard);
        manager.addBackend(simBackend);

        YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager()
    }

    public static void main(String[] args)
    {
        runTest(new MultiBackendTest());
    }
}
