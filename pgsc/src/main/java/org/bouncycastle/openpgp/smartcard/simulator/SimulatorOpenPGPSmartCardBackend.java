package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;

import java.util.ArrayList;
import java.util.List;

public class SimulatorOpenPGPSmartCardBackend
        extends OpenPGPSmartCardBackend<SimulatorOpenPGPSmartCard>
{
    private final List<SimulatorOpenPGPSmartCard> smartCards = new ArrayList<>();

    public SimulatorOpenPGPSmartCardBackend()
    {
        this(new BcOpenPGPSmartCardImplementation());
    }

    public SimulatorOpenPGPSmartCardBackend(OpenPGPSmartCardImplementation implementation)
    {
        super(implementation);
    }

    @Override
    public String getName()
    {
        return "Simulator";
    }

    public SimulatorOpenPGPSmartCardBackend addSmartCard(SimulatorOpenPGPSmartCard card)
    {
        this.smartCards.add(card);
        return this;
    }

    @Override
    public List<SimulatorOpenPGPSmartCard> listSmartCards()
    {
        return smartCards;
    }
}
