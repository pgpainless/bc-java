package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import static org.bouncycastle.util.Strings.toUTF8ByteArray;

/**
 * Signature subpacket storing the SHA256 hash of a LiteralDataPackets metadata.
 * Only for use with v4 signatures.
 * Only for use with LibrePGP.
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-literal-data-meta-hash">
 *     LibrePGP - Literal Data Meta Hash</a>
 */
public class LiteralDataMetaHash
        extends SignatureSubpacket implements SignatureSubpacketTags
{

    public LiteralDataMetaHash(boolean isCritical, byte contentFormat, String filename, Date modificationDate)
            throws NoSuchAlgorithmException
    {
        this(isCritical, true, hash(contentFormat, filename, modificationDate));
    }

    public LiteralDataMetaHash(boolean critical, boolean isLongLength, byte[] hash)
    {
        super(LIBREPGP_LITERAL_DATA_META_HASH, critical, isLongLength, hash);
    }

    public static byte[] hash(byte contentFormat, String filename, Date modificationDate)
            throws NoSuchAlgorithmException
    {
        MessageDigest sha256 = MessageDigest.getInstance("SHA256");
        byte[] filenameBytes = toUTF8ByteArray(filename);
        byte[] data = new byte[1 + 1 + filenameBytes.length + 4];
        data[0] = contentFormat;
        data[1] = (byte) filenameBytes.length;
        System.arraycopy(filenameBytes, 0, data, 2, filenameBytes.length);
        long time = modificationDate.getTime();
        data[data.length - 4] = (byte) (time >> 24);
        data[data.length - 3] = (byte) (time >> 16);
        data[data.length - 2] = (byte) (time >> 8);
        data[data.length - 1] = (byte) time;
        return sha256.digest(data);
    }

    /**
     * Return the SHA256 hash of the {@link org.bouncycastle.bcpg.LiteralDataPacket} metadata.
     * @return hash
     */
    public byte[] getMetadataHash()
    {
        return data;
    }
}
