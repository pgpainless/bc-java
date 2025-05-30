package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;

public interface SnovaKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SnovaParameterSpec
     */
    SnovaParameterSpec getParameterSpec();
}
