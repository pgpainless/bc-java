package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class OpenPGPKey
        extends OpenPGPCertificate
{

    public OpenPGPKey(PGPSecretKeyRing rawKey,
                      PGPContentVerifierBuilderProvider contentVerifierBuilderProvider)
    {
        super(rawKey, contentVerifierBuilderProvider);
    }

    @Override
    public PGPSecretKeyRing getPGPKeyRing()
    {
        return (PGPSecretKeyRing) super.getPGPKeyRing();
    }

    @Override
    public String toAsciiArmoredString()
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream.Builder armorBuilder = ArmoredOutputStream.builder()
                .clearHeaders();

        for (String slice : fingerprintComments())
        {
            armorBuilder.addComment(slice);
        }

        for (OpenPGPUserId userId : getPrimaryKey().getUserIDs())
        {
            armorBuilder.addComment(userId.getUserId());
        }

        ArmoredOutputStream aOut = armorBuilder.build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        getPGPKeyRing().encode(pOut);
        pOut.close();
        aOut.close();
        return bOut.toString();
    }
}
