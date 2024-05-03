package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature subpacket holding a certificate containing the signing key.
 * Only for use with LibrePGP.
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-key-block">
 *     LibrePGP - Key Block</a>
 */
public class KeyBlock
        extends SignatureSubpacket implements SignatureSubpacketTags
{

    public KeyBlock(boolean critical, boolean isLongLength, byte[] data)
    {
        super(LIBREPGP_KEY_BLOCK, critical, isLongLength, data);
    }

    /**
     * Return the signing certificate.
     * @return certificate
     */
    public byte[] getCertificate()
    {
        return data;
    }
}
