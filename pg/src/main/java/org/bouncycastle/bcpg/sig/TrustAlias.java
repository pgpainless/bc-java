package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

import static org.bouncycastle.util.Strings.toUTF8ByteArray;

/**
 * Signature subpacket containing a user-id alias.
 * Only for use with LibrePGP.
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-trust-alias">
 *     LibrePGP - Trust Alias</a>
 */
public class TrustAlias
        extends SignatureSubpacket implements SignatureSubpacketTags
{
    public TrustAlias(boolean critical, boolean isLongLength, byte[] data)
    {
        super(LIBREPGP_TRUST_ALIAS, critical, isLongLength, data);
    }

    public TrustAlias(boolean isCritical, boolean isLongLength, String userIdAlias)
    {
        this(isCritical, isLongLength, toUTF8ByteArray(userIdAlias));
    }
}
