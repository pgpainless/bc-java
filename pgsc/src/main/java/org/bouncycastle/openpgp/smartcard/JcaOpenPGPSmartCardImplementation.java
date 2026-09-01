package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPImplementation;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.operator.jcajce.JceSmartCardPublicKeyDataDecryptorFactoryBuilder;

import java.security.SecureRandom;

public class JcaOpenPGPSmartCardImplementation
        extends OpenPGPSmartCardImplementation
{
    public JcaOpenPGPSmartCardImplementation()
    {
        this(new JcaOpenPGPImplementation(new BouncyCastleProvider(), new SecureRandom()));
    }

    public JcaOpenPGPSmartCardImplementation(JcaOpenPGPImplementation implementation)
    {
        super(implementation);
    }

    @Override
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            OpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        return new JceSmartCardPublicKeyDataDecryptorFactoryBuilder<>(card, userPinProvider)
                .setProvider(((JcaOpenPGPImplementation)implementation).getProvider())
                .build(secretKey);
    }

    @Override
    public String getName()
    {
        return "JCE";
    }
}
