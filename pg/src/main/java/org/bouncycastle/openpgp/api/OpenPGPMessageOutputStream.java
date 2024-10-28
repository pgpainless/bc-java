package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Stack;

public class OpenPGPMessageOutputStream
        extends OutputStream
{

    private final Stack<OutputStream> layers = new Stack<>();
    private final OutputStream base;

    public OpenPGPMessageOutputStream(OutputStream base)
    {
        this.base = base;
    }

    OutputStream top()
    {
        return layers.isEmpty() ? base : layers.peek();
    }

    void addLayer(OutputStreamFactory factory)
            throws PGPException
    {
        layers.push(factory.get(top()));
    }

    @Override
    public void write(int i)
            throws IOException
    {
        top().write(i);
    }

    @Override
    public void write(byte[] b)
            throws IOException
    {
        top().write(b);
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException
    {
        top().write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        for (OutputStream layer : layers)
        {
            layer.flush();
        }
    }

    @Override
    public void close()
            throws IOException
    {
        for (OutputStream layer : layers)
        {
            layer.close();
        }
    }

    public interface OutputStreamFactory
    {
        OutputStream get(OutputStream base) throws PGPException;
    }
}
