package org.bouncycastle.crypto.params;

public abstract class MLKEMECCKeyParameters<
        E extends AsymmetricKeyParameter,
        M extends AsymmetricKeyParameter>
        extends AsymmetricKeyParameter
{
    protected E eccKeyParameter;
    protected M mlkemKeyParameter;

    protected MLKEMECCKeyParameters(
            boolean isPrivate,
            E eccKeyParameter,
            M mlkemKeyParameter)
    {
        super(isPrivate);
        this.eccKeyParameter = eccKeyParameter;
        this.mlkemKeyParameter = mlkemKeyParameter;

        if (eccKeyParameter.isPrivate() != isPrivate)
        {
            throw new IllegalArgumentException("Expected ECC key component to be " + (isPrivate ? "private" : "public"));
        }
        if (mlkemKeyParameter.isPrivate() != isPrivate)
        {
            throw new IllegalArgumentException("Expected ML-KEM key component to be " + (isPrivate ? "private" : "public"));
        }
    }

    public E getEccKeyParameter()
    {
        return eccKeyParameter;
    }

    public M getMlKemKeyParameter()
    {
        return mlkemKeyParameter;
    }

    protected abstract int getEccKeySize();

    protected abstract int getMlKemKeySize();

    protected abstract byte[] getEncodedEccKey();

    protected abstract byte[] getEncodedMlKemKey();

    protected int getKeySize()
    {
        return getEccKeySize() + getMlKemKeySize();
    }

    public byte[] getEncoded()
    {
        byte[] data = new byte[getKeySize()];
        encode(data, 0);
        return data;
    }

    public void encode(byte[] buf, int off)
    {
        byte[] ecc = getEncodedEccKey();
        System.arraycopy(ecc, 0, buf, off, getEccKeySize());
        byte[] mlkem = getEncodedMlKemKey();
        System.arraycopy(mlkem, 0, buf, off + getEccKeySize(), getMlKemKeySize());
    }

    protected static byte[] validate(byte[] buf, int keySize)
    {
        if (buf.length != keySize)
        {
            throw new IllegalArgumentException("'buf' must have length " + keySize);
        }
        return buf;
    }
}
