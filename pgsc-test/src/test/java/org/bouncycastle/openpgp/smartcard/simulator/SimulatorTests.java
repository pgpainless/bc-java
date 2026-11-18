package org.bouncycastle.openpgp.smartcard.simulator;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestSuite;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;

import java.util.List;

public class SimulatorTests
        extends TestCase
{
    public void testOnSimulatorSmartCard()
    {
        // Prepare implementation
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        OpenPGPSmartCardManager m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        AbstractOpenPGPSmartCardTest.TestProperties p = new AbstractOpenPGPSmartCardTest.TestProperties(1312);

        // Collect tests
        List<Test> tests = SmartCardTestSuite.getGenericTestsFor(m, p);
        tests.add(new SimulatorSmartCardTest(m, p));

        // Run tests
        for (int i = 0; i != tests.size(); i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests.get(i).perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    public static void main(String[] args)
    {
        new SimulatorTests().testOnSimulatorSmartCard();
    }
}
