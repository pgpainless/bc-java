package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SmartCardTestSetup
{
    private final Map<OpenPGPSmartCardBackend, List<SmartCardTestProperties>> backends = new HashMap<>();

    public SmartCardTestSetup(Map<OpenPGPSmartCardBackend, List<SmartCardTestProperties>> backends)
    {
        this.backends.putAll(backends);
    }

    public List<OpenPGPSmartCardBackend> getBackends()
    {
        return new ArrayList<>(backends.keySet());
    }

    public List<SmartCardTestProperties> getTestProperties(OpenPGPSmartCardBackend backend)
    {
        return new ArrayList<>(backends.get(backend));
    }
}
