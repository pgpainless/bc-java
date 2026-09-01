package org.bouncycastle.openpgp.smartcard.yubikey;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.util.Arrays;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class YubikeyOpenPGPSmartCardBackend
        extends OpenPGPSmartCardBackend<YubikeyOpenPGPSmartCard>
{
    private static final int X25519_SCALAR_SIZE = 32;

    private final JcaPGPKeyConverter converter;
    private boolean useAllowList = true;
    private final Set<Integer> allowedCardSerials = new HashSet<>();
    private final YubiKitManager manager;

    public static YubikeyOpenPGPSmartCardBackend createInstance()
    {
        return createInstance(new BcOpenPGPSmartCardImplementation());
    }

    public static YubikeyOpenPGPSmartCardBackend createInstance(OpenPGPSmartCardImplementation implementation)
    {
        return createInstance(new YubiKitManager(),
                implementation);
    }

    public static YubikeyOpenPGPSmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                                OpenPGPSmartCardImplementation implementation)
    {
        return createInstance(yubiKitManager,
                new BouncyCastleProvider(),
                implementation);
    }

    public static YubikeyOpenPGPSmartCardBackend createInstance(YubiKitManager yubiKitManager,
                                                                BouncyCastleProvider provider,
                                                                OpenPGPSmartCardImplementation implementation)
    {
        return new YubikeyOpenPGPSmartCardBackend(
                yubiKitManager,
                new JcaPGPKeyConverter().setProvider(provider),
                implementation);
    }

    public YubikeyOpenPGPSmartCardBackend(YubiKitManager yubiKitManager,
                                          JcaPGPKeyConverter keyConverter,
                                          OpenPGPSmartCardImplementation implementation)
    {
        super(implementation);
        this.manager = yubiKitManager;
        this.converter = keyConverter;
    }

    @Override
    public String getName()
    {
        return implementation.getName() + "+Yubikit";
    }

    /**
     * Return the connected YubiKey devices whose serial number has been allow-listed with
     * {@link #addAllowedCardSerial(Integer)}. Devices that have not been allow-listed are never opened,
     * so no APDU is exchanged with a device the caller did not nominate; a backend with an empty
     * allow-list therefore always returns an empty list.
     * Note: The allow-list can be disabled with {@link #setEnableAllowList(boolean)} passing in <pre>false</pre>.
     * If the allow-list is disabled, any device can be opened, regardless of whether it was allow-listed.
     *
     * @return allow-listed smart cards
     * @throws CardException if the device layer cannot be queried, or a nominated device cannot be read
     */
    @Override
    public List<YubikeyOpenPGPSmartCard> listSmartCards()
            throws CardException
    {
        if (useAllowList && allowedCardSerials.isEmpty())
        {
            return new ArrayList<YubikeyOpenPGPSmartCard>();
        }

        Map<YubiKeyDevice, DeviceInfo> allDevices;
        try
        {
            allDevices = manager.listAllDevices();
        }
        catch (RuntimeException e)
        {
            // the desktop backend throws unchecked when no PC/SC service or reader is available; that is
            // "nothing plugged in", but it is also how a genuine fault surfaces, so keep the cause.
            throw new CardException("Cannot enumerate YubiKey devices.", e);
        }

        List<YubikeyOpenPGPSmartCard> allowedDevices = new ArrayList<YubikeyOpenPGPSmartCard>();
        for (Iterator<Map.Entry<YubiKeyDevice, DeviceInfo>> it = allDevices.entrySet().iterator(); it.hasNext();)
        {
            Map.Entry<YubiKeyDevice, DeviceInfo> entry = it.next();
            // check the allow-list against the serial the device layer already reported, before opening
            // a session against the card
            if (useAllowList && !allowedCardSerials.contains(entry.getValue().getSerialNumber()))
            {
                continue;
            }
            allowedDevices.add(new YubikeyOpenPGPSmartCard(this, entry.getValue(), entry.getKey()));
        }
        return allowedDevices;
    }

    /**
     * Nominate a device serial number this backend is permitted to open. Nothing is enumerated until at
     * least one serial has been added - see {@link #listSmartCards()}.
     *
     * @param number device serial number
     * @return this
     */
    public YubikeyOpenPGPSmartCardBackend addAllowedCardSerial(Integer number)
    {
        allowedCardSerials.add(number);
        return this;
    }

    /**
     * Configure the backend to limit the set of permitted devices to those on the allow-list.
     * If the allow-list is disabled by passing in <pre>false</pre> any device will be permitted to be opened.
     *
     * @return this
     */
    public YubikeyOpenPGPSmartCardBackend setEnableAllowList(boolean enableAllowList)
    {
        useAllowList = enableAllowList;
        return this;
    }

    PrivateKeyValues convertPrivateKey(PGPKeyPair keyPair)
            throws PGPException
    {
        final PrivateKey converted = converter.getPrivateKey(keyPair.getPrivateKey());
        if (!PublicKeyUtils.isX25519Key(keyPair.getPublicKey().getPublicKeyPacket()))
        {
            return PrivateKeyValues.fromPrivateKey(converted);
        }

        return PrivateKeyValues.fromPrivateKey(new PrivateKey()
        {
            public String getAlgorithm()
            {
                return converted.getAlgorithm();
            }

            public String getFormat()
            {
                return converted.getFormat();
            }

            public byte[] getEncoded()
            {
                // the YubiKey expects the X25519 scalar big-endian, the reverse of the PKCS#8 encoding.
                // Copy first: getEncoded() is not contractually required to hand back a fresh array, and
                // reversing in place would corrupt the source key for any provider that shares one.
                byte[] encoding = Arrays.clone(converted.getEncoded());
                if (encoding == null || encoding.length < X25519_SCALAR_SIZE)
                {
                    throw new IllegalStateException("X25519 private key encoding too short to contain a scalar");
                }
                Arrays.reverseInPlace(encoding, encoding.length - X25519_SCALAR_SIZE, X25519_SCALAR_SIZE);
                return encoding;
            }
        });
    }

    PublicKeyValues convertPublicKey(PGPPublicKey pgpPublicKey)
            throws PGPException
    {
        try
        {
            return PublicKeyValues.fromPublicKey(converter.getPublicKey(pgpPublicKey));
        }
        catch (IllegalStateException e)
        {
            throw new PGPException("Cannot convert PGPPublicKey to PublicKeyValues", e);
        }
    }

    /**
     * Convert the key from {@link PublicKeyValues} into a bare {@link PGPPublicKey}, brute-forcing the
     * algorithm id.
     * Brute-forcing is done by comparing the fingerprint of the reconstructed PGP key to the fingerprint
     * stored on the key.
     *
     * @param pkVal Yubikey PublicKeyValues
     * @param storedFingerprint fingerprint as it is stored on the Yubikey device
     * @param creationTime creation time as it is stored on the Yubikey device
     * @return converted PGP public key
     *
     * @throws PGPException if the key cannot be reconstructed
     * @throws NoSuchAlgorithmException if no Provider supports an implementation for the PublicKeyValues algorithm
     * @throws InvalidKeySpecException if the PublicKeyValues specification is inappropriate to produce a public key
     */
    public PGPPublicKey convertPublicKey(PublicKeyValues pkVal,
                                    byte[] storedFingerprint,
                                    Date creationTime)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        PublicKey pk = pkVal.toPublicKey();
        String alg = pk.getAlgorithm();
        int[] candidates;
        if ("RSA".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_ENCRYPT,
                PublicKeyAlgorithmTags.RSA_SIGN};
        }
        else if ("EC".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.ECDH};
        }
        else if ("EdDSA".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed25519,
                PublicKeyAlgorithmTags.Ed448};
        }
        else if ("XDH".equals(alg))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X25519};
        }
        else
        {
            throw new PGPException("Cannot reconstruct public " + alg + " PGP key.");
        }

        PGPPublicKey pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint, candidates);
        if (pgpKey == null)
        {
            throw new PGPException("Cannot reconstruct public " + alg + " PGP key.");
        }
        return pgpKey;
    }

    private PGPPublicKey bruteForcePublicKey(PublicKey pk, Date creationTime,
                                             byte[] storedFingerprint,
                                             int[] plausibleAlgorithms)
    {
        for (int keyVersion : new int[]{PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6})
        {
            for (int i = 0; i != plausibleAlgorithms.length; i++)
            {
                int algorithm = plausibleAlgorithms[i];
                PGPPublicKey pgpKey;
                try
                {
                    pgpKey = converter.getPGPPublicKey(keyVersion, algorithm, pk, creationTime);
                }
                catch (PGPException e)
                {
                    // this candidate algorithm cannot represent the key at all (e.g. an Ed448 tag over an
                    // Ed25519 key) - that is a miss, not a failure of the whole search.
                    continue;
                }

                if (fingerprintMatches(storedFingerprint, pgpKey.getFingerprint()))
                {
                    return pgpKey;
                }
            }
        }
        return null;
    }
}
