package org.bouncycastle.openpgp.api;

import java.util.ArrayList;
import java.util.List;

public class NotationRegistry
{

    private final List<String> knownNotations = new ArrayList<>();

    public boolean isNotationKnown(String notationName)
    {
        return knownNotations.contains(notationName);
    }

    public void addKnownNotation(String notationName)
    {
        this.knownNotations.add(notationName);
    }
}
