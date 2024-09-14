package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.OutputStream;

public class LibrePGPLiteralDataMetaHash
        extends SignatureSubpacket
{
    public LibrePGPLiteralDataMetaHash(boolean critical, boolean longLength, byte[] data)
            throws IOException
    {
        super(SignatureSubpacketTags.LIBREPGP_LITERAL_DATA_META_HASH, critical, longLength, data);
        if (data[0] != 0 || data.length != 32 + 1)
        {
            throw new IOException("Invalid LiteralDataMetaHash subpacket.");
        }
    }

    public LibrePGPLiteralDataMetaHash(boolean critical, byte[] sha256Hash)
    {
        super(
                SignatureSubpacketTags.LIBREPGP_LITERAL_DATA_META_HASH,
                critical,
                false,
                Arrays.prepend(sha256Hash, (byte) 0));
    }

    public static LibrePGPLiteralDataMetaHash create(
            boolean critical,
            int contentFormat,
            byte[] fileName,
            long modificationDate,
            PGPDigestCalculatorProvider calculatorProvider)
            throws PGPException
    {
        return new LibrePGPLiteralDataMetaHash(critical,
                hash(
                        (byte) contentFormat,
                        fileName,
                        modificationDate,
                        calculatorProvider
                ));
    }

    public static LibrePGPLiteralDataMetaHash createDetachedSignatureMetadata(
            boolean critical,
            PGPDigestCalculatorProvider calculatorProvider)
            throws PGPException
    {
        return create(
                critical,
                PGPLiteralData.BINARY,
                new byte[0],
                0L,
                calculatorProvider);
    }

    public static byte[] hash(byte contentFormat,
                              byte[] fileName,
                              long modificationDate,
                              PGPDigestCalculatorProvider calculatorProvider)
            throws PGPException
    {
        byte[] metadata = Arrays.concatenate(
                new byte[] {contentFormat},
                new byte[] {(byte) fileName.length},
                fileName,
                Utils.timeToBytes(modificationDate));
        PGPDigestCalculator calculator = calculatorProvider.get(HashAlgorithmTags.SHA256);
        OutputStream hOut = calculator.getOutputStream();
        try
        {
            hOut.write(metadata);
            hOut.close();
        }
        catch (IOException e)
        {
            throw new PGPException("Cannot calculate SHA256 hash from metadata packet");
        }
        return calculator.getDigest();
    }

    public boolean verify(int contentFormat,
                          byte[] fileName,
                          long modificationDate,
                          PGPDigestCalculatorProvider calculatorProvider)
            throws PGPException
    {
        return Arrays.constantTimeAreEqual(
                Arrays.copyOfRange(data, 1, 33),
                hash((byte) contentFormat, fileName, modificationDate, calculatorProvider));
    }
}
