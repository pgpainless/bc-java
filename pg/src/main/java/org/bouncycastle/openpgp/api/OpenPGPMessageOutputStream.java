package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Stack;

/**
 * Implementation of an {@link OutputStream} tailored to creating OpenPGP messages.
 * Since not all OpenPGP-related OutputStreams forward {@link #close()} calls, we need to keep track of nested streams
 * and close them in order.
 */
public class OpenPGPMessageOutputStream
        extends OutputStream
{
    private final OutputStream baseOut;
    private final OutputStream armorOut;
    private final OutputStream encodeOut;
    private final OutputStream encryptOut;
    private final OutputStream paddingOut;
    private final OutputStream signOut;
    private final OutputStream compressOut;
    private final OutputStream literalOut;

    private final OutputStream plaintextOut;

    public OpenPGPMessageOutputStream(
            OutputStream baseOut,
            OutputStream armorOut,
            OutputStream encodeOut,
            OutputStream encryptOut,
            OutputStream paddingOut,
            OutputStream signOut,
            OutputStream compressOut,
            OutputStream literalOut)
    {
        this.baseOut = baseOut;
        this.armorOut = armorOut;
        this.encodeOut = encodeOut;
        this.encryptOut = encryptOut;
        this.paddingOut = paddingOut;
        this.signOut = signOut;
        this.compressOut = compressOut;
        this.literalOut = literalOut;

        if (signOut != null)
        {
            this.plaintextOut = new TeeOutputStream(literalOut, signOut);
        }
        else
        {
            this.plaintextOut = literalOut;
        }
    }

    @Override
    public void write(int i)
            throws IOException
    {
        plaintextOut.write(i);
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
        plaintextOut.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        literalOut.flush();
        if (compressOut != null)
        {
            compressOut.flush();
        }
        if (signOut != null)
        {
            signOut.flush();
        }
        if (paddingOut != null)
        {
            paddingOut.flush();
        }
        if (encryptOut != null)
        {
            encryptOut.flush();
        }
        encodeOut.flush();
        if (armorOut != null)
        {
            armorOut.flush();
        }
        baseOut.flush();
    }

    @Override
    public void close()
            throws IOException
    {
        literalOut.close();
        if (compressOut != null)
        {
            compressOut.close();
        }
        if (signOut != null)
        {
            signOut.close();
        }
        if (paddingOut != null)
        {
            paddingOut.close();
        }
        if (encryptOut != null)
        {
            encryptOut.close();
        }
        encodeOut.close();
        if (armorOut != null)
        {
            armorOut.close();
        }
        baseOut.close();
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
        OutputStream get(OutputStream base) throws PGPException, IOException;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private OpenPGPMessageGenerator.ArmoredOutputStreamFactory armorFactory;
        private OutputStreamFactory paddingStreamFactory;
        private OutputStreamFactory encryptionStreamFactory;
        private OutputStreamFactory signatureStreamFactory;
        private OutputStreamFactory compressionStreamFactory;
        private OutputStreamFactory literalDataStreamFactory;

        public Builder armor(OpenPGPMessageGenerator.ArmoredOutputStreamFactory factory)
        {
            this.armorFactory = factory;
            return this;
        }

        public Builder encrypt(OutputStreamFactory factory)
        {
            this.encryptionStreamFactory = factory;
            return this;
        }

        public Builder padding(OutputStreamFactory factory)
        {
            this.paddingStreamFactory = factory;
            return this;
        }

        public Builder sign(OutputStreamFactory factory)
        {
            this.signatureStreamFactory = factory;
            return this;
        }

        public Builder compress(OutputStreamFactory factory)
        {
            this.compressionStreamFactory = factory;
            return this;
        }

        public Builder literalData(OutputStreamFactory factory)
        {
            this.literalDataStreamFactory = factory;
            return this;
        }

        public OpenPGPMessageOutputStream build(OutputStream baseOut)
                throws PGPException, IOException
        {
            OutputStream innermostOut = baseOut;

            // ASCII ARMOR
            OutputStream armorOut = null;
            if (armorFactory != null)
            {
                armorOut = armorFactory.get(innermostOut);
                innermostOut = armorOut;
            }

            // BCPG
            OutputStream encodeOut = new BCPGOutputStream(innermostOut, PacketFormat.CURRENT);
            innermostOut = encodeOut;

            // ENCRYPT
            OutputStream encryptOut = null;
            if (encryptionStreamFactory != null)
            {
                encryptOut = encryptionStreamFactory.get(innermostOut);
                innermostOut = encryptOut;
            }

            // PADDING
            OutputStream paddingOut = null;
            if (paddingStreamFactory != null)
            {
                paddingOut = paddingStreamFactory.get(innermostOut);
                innermostOut = paddingOut;
            }

            // SIGN
            OutputStream signOut = null;
            if (signatureStreamFactory != null)
            {
                signOut = signatureStreamFactory.get(innermostOut);
                // signOut does not forward write() calls down, so we do *not* set innermostOut to it
            }

            // COMPRESS
            OutputStream compressOut = null;
            if (compressionStreamFactory != null)
            {
                compressOut = compressionStreamFactory.get(innermostOut);
                innermostOut = compressOut;
            }

            // LITERAL DATA
            if (literalDataStreamFactory == null)
            {
                throw new PGPException("Missing instructions for LiteralData encoding.");
            }

            OutputStream literalOut = literalDataStreamFactory.get(innermostOut);
            innermostOut = literalOut;

            return new OpenPGPMessageOutputStream(baseOut, armorOut, encodeOut, encryptOut, paddingOut, signOut, compressOut, literalOut);
        }
    }

    public static class SignerOutputStream
            extends OutputStream
    {

        private final OutputStream out;
        private final Stack<PGPSignatureGenerator> signatureGenerators;

        public SignerOutputStream(OutputStream out, Stack<PGPSignatureGenerator> signatureGenerators)
        {
            this.out = out;
            this.signatureGenerators = signatureGenerators;
        }

        @Override
        public void write(int i)
                throws IOException
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update((byte) i);
            }
        }

        @Override
        public void write(byte[] b)
                throws IOException
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update(b);
            }
        }

        @Override
        public void write(byte[] b, int off, int len)
                throws IOException
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update(b, off, len);
            }
        }

        @Override
        public void close()
                throws IOException
        {
            while (!signatureGenerators.isEmpty())
            {
                PGPSignatureGenerator gen = signatureGenerators.pop();
                PGPSignature sig = null;
                try {
                    sig = gen.generate();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
                sig.encode(out);
            }
        }
    }

    public static class PaddingPacketAppenderOutputStream
            extends OutputStream
    {
        private final OutputStream out;
        private final PaddingPacketFactory packetFactory;

        public PaddingPacketAppenderOutputStream(OutputStream out, PaddingPacketFactory packetFactory)
        {
            this.out = out;
            this.packetFactory = packetFactory;
        }

        @Override
        public void write(byte[] b)
                throws IOException
        {
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len)
                throws IOException
        {
            out.write(b, off, len);
        }

        @Override
        public void write(int i)
                throws IOException
        {
            out.write(i);
        }

        @Override
        public void close()
                throws IOException
        {
            packetFactory.providePaddingPacket().encode(out);
            out.close();
        }
    }

    public interface PaddingPacketFactory
    {
        PGPPadding providePaddingPacket();
    }
}
