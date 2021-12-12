package org.bouncycastle.bcpg.sig;

import java.net.URI;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Strings;

public class PreferredKeyServer
        extends SignatureSubpacket
{

    private final URI uri;

    public PreferredKeyServer(boolean critical, URI keyServer)
    {
        super(SignatureSubpacketTags.PREFERRED_KEY_SERV, critical, false, Strings.toUTF8ByteArray(keyServer.toString()));
        this.uri = keyServer;
    }

    public PreferredKeyServer(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.PREFERRED_KEY_SERV, critical, isLongLength, data);
        this.uri = URI.create(Strings.fromUTF8ByteArray(data));
    }

    public URI getUri()
    {
        return uri;
    }
}
