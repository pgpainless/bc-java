package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class AEADPublicBCPGKey
        extends PersistentSymmetricBCPGPublicKey
{
    private final int symmetricKeyAlgorithmId;
    private final int aeadAlgorithmId;
    private final byte[] fingerprintSeed;

    public AEADPublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        this.symmetricKeyAlgorithmId = in.read();
        this.aeadAlgorithmId = in.read();
        this.fingerprintSeed = expectSeed(in.readAll());
    }

    public AEADPublicBCPGKey(int symmetricKeyAlgorithmId,
                             int aeadAlgorithmId,
                             byte[] fingerprintSeed)
            throws IOException
    {
        this.symmetricKeyAlgorithmId = symmetricKeyAlgorithmId;
        this.aeadAlgorithmId = aeadAlgorithmId;
        this.fingerprintSeed = expectSeed(fingerprintSeed);
    }

    public AEADPublicBCPGKey(int symmetricKeyAlgorithmId,
                             int aeadAlgorithmId)
    {
        this.symmetricKeyAlgorithmId = symmetricKeyAlgorithmId;
        this.aeadAlgorithmId = aeadAlgorithmId;
        this.fingerprintSeed = createSeed();
    }

    public int getSymmetricKeyAlgorithmId()
    {
        return symmetricKeyAlgorithmId;
    }

    public int getAeadAlgorithmId()
    {
        return aeadAlgorithmId;
    }

    @Override
    public byte[] getFingerprintSeed()
    {
        return Arrays.clone(fingerprintSeed);
    }

    @Override
    public void encode(BCPGOutputStream out)
            throws IOException
    {
        out.write(symmetricKeyAlgorithmId);
        out.write(aeadAlgorithmId);
        out.write(fingerprintSeed);
    }

}
