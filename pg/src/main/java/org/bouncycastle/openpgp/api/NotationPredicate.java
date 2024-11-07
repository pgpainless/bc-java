package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.sig.NotationData;

public interface NotationPredicate
{
    boolean accept(NotationData notation);

    static NotationPredicate fromNotationRegistry(NotationRegistry registry)
    {
        return notation -> !notation.isCritical() || registry.isNotationKnown(notation.getNotationName());
    }
}
