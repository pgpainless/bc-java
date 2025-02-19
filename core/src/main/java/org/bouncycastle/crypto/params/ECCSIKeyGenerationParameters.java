package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class ECCSIKeyGenerationParameters
    extends KeyGenerationParameters
{
    private static final BigInteger q;
    private static final ECPoint G;

    static
    {
        X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
        q = params.getCurve().getOrder();
        G = params.getG();
    }

    private final byte[] id;
    private final BigInteger ksak;
    private final ECPoint kpak;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random the random byte source.
     */
    public ECCSIKeyGenerationParameters(SecureRandom random, byte[] id)
    {
        super(random, 256);
        this.id = Arrays.clone(id);
        this.ksak = new BigInteger(256, random).mod(q);
        this.kpak = G.multiply(ksak).normalize();
    }

    public byte[] getId()
    {
        return id;
    }

    public ECPoint getKPAK()
    {
        return kpak;
    }

    public BigInteger computeSSK(BigInteger hs_v)
    {
        return ksak.add(hs_v).mod(q);
    }
}
