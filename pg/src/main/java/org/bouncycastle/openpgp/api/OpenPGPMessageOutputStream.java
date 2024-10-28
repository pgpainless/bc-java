package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Stack;

/**
 * Implementation of an {@link OutputStream} tailored to creating OpenPGP messages.
 * Since not all OpenPGP-related OutputStreams forward {@link #close()} calls, we need to keep track of nested streams
 * and close them in order.
 */
public class OpenPGPMessageOutputStream
        extends OutputStream
{
    private final Stack<OutputStream> layers = new Stack<>();
    private final OutputStream base;

    public OpenPGPMessageOutputStream(OutputStream base)
    {
        this.base = base;
    }

    /**
     * Return the top-most {@link OutputStream}.
     *
     * @return top-most stream
     */
    OutputStream top()
    {
        return layers.isEmpty() ? base : layers.peek();
    }

    /**
     * Wrap the top-most {@link OutputStream} by creating a new stream using the passed in factory and push it to
     * the top of the layer stack.
     *
     * @param factory output stream factory
     * @throws PGPException if the stream cannot be instantiated
     */
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
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException
    {
        top().write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        // Stack iteration is unfortunately bottom to top, so we need to use indices to iterate
        //  "in reverse" top to bottom
        for (int i = layers.size() - 1; i >= 0; i--)
        {
            OutputStream layer = layers.get(i);
            layer.flush();
        }
    }

    @Override
    public void close()
            throws IOException
    {
        // Stack iteration is unfortunately bottom to top, so we need to use indices to iterate
        //  "in reverse" top to bottom
        for (int i = layers.size() - 1; i >= 0; i--)
        {
            OutputStream layer = layers.get(i);
            layer.flush();
            layer.close();
        }
    }

    /**
     * Factory class for wrapping output streams.
     */
    public interface OutputStreamFactory
    {
        /**
         * Wrap the given base stream with another {@link OutputStream} and return the result.
         * @param base base output stream
         * @return wrapped output stream
         * @throws PGPException if the wrapping stream cannot be instantiated
         */
        OutputStream get(OutputStream base) throws PGPException;
    }
}
