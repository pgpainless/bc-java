package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.InputStream;

public class MLKEM768X25519PrivateKeyParameters
        extends MLKEMECCKeyParameters<X25519PrivateKeyParameters, MLKEMPrivateKeyParameters>
{
    public static final int MLKEM768_SIZE = 64;
    public static final int KEY_SIZE = X25519.POINT_SIZE + MLKEM768_SIZE;

    public MLKEM768X25519PrivateKeyParameters(byte[] buf)
    {
        super(true,
                parseECCComponent(validate(buf, KEY_SIZE)),
                parseMlKemComponent(buf));
    }

    public MLKEM768X25519PrivateKeyParameters(InputStream input)
            throws IOException
    {
        this(Streams.readAll(input));
    }

    private MLKEM768X25519PrivateKeyParameters(
            X25519PrivateKeyParameters x25519PrivateKey,
            MLKEMPrivateKeyParameters mlKemPrivateKey)
    {
        super(true, x25519PrivateKey, mlKemPrivateKey);
    }

    @Override
    protected byte[] getEncodedEccKey()
    {
        return getEccKeyParameter().getEncoded();
    }

    @Override
    protected byte[] getEncodedMlKemKey()
    {
        return getMlKemKeyParameter().getEncoded();
    }

    @Override
    protected int getEccKeySize()
    {
        return X25519PrivateKeyParameters.KEY_SIZE;
    }

    @Override
    protected int getMlKemKeySize()
    {
        return MLKEM768_SIZE;
    }

    private static X25519PrivateKeyParameters parseECCComponent(byte[] bytes)
    {
        byte[] x25519 = new byte[X25519.POINT_SIZE];
        System.arraycopy(bytes, 0, x25519, 0, x25519.length);
        return new X25519PrivateKeyParameters(x25519);
    }

    private static MLKEMPrivateKeyParameters parseMlKemComponent(byte[] bytes)
    {
        byte[] mlkem = new byte[MLKEM768_SIZE];
        System.arraycopy(bytes, X25519.POINT_SIZE, mlkem, 0, mlkem.length);
        return new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, mlkem);
    }
}
