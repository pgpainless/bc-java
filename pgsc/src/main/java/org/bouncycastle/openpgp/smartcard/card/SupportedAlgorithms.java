package org.bouncycastle.openpgp.smartcard.card;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;

import java.util.ArrayList;
import java.util.List;

/**
 * List of supported algorithms of a Smart Card.
 */
public class SupportedAlgorithms
{

    private final List<Algorithm> algorithms = new ArrayList<>();

    public SupportedAlgorithms(List<Algorithm> algorithms)
    {
        this.algorithms.addAll(algorithms);
    }

    public List<Algorithm> getAlgorithms()
    {
        return new ArrayList<>(algorithms);
    }

    public boolean supports(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        for (Algorithm algorithm : algorithms)
        {
            if (algorithm.matches(key))
            {
                return true;
            }
        }
        return false;
    }

    public static abstract class Algorithm
    {
        public final byte keyRef;
        public final int algorithmId;

        public Algorithm(byte keyRef, int algorithmId)
        {
            this.keyRef = keyRef;
            this.algorithmId = algorithmId;
        }

        public abstract boolean matches(OpenPGPCertificate.OpenPGPComponentKey key);

        public abstract String toString();
    }

    public static class RSA extends Algorithm
    {
        public final int keySize;

        public RSA(byte keyRef, int algorithmId, int keySize)
        {
            super(keyRef, algorithmId);
            this.keySize = keySize;
        }

        @Override
        public boolean matches(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            if (key.getPGPPublicKey().getAlgorithm() == algorithmId)
            {
                return key.getPGPPublicKey().getBitStrength() == keySize;
            }
            return false;
        }

        @Override
        public String toString()
        {
            return "Rsa{algorithmId=" + algorithmId + ", keySize=" + keySize + '}';
        }
    }

    public static class EC extends Algorithm
    {
        public final ASN1ObjectIdentifier curve;

        public EC(byte keyRef, int algorithmId, ASN1ObjectIdentifier curve)
        {
            super(keyRef, algorithmId);
            this.curve = curve;
        }

        @Override
        public boolean matches(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            ASN1ObjectIdentifier keyCurve = getKeyCurveOID(key);
            int keyAlgorithm = key.getAlgorithm();

            // Explicit match (NIST, Brainpool curves)
            if (algorithmId == keyAlgorithm)
            {
                if (curve.equals(keyCurve))
                {
                    return true;
                }
            }

            // Manual matches

            // card advertises support for Ed25519 as EDDSA_LEGACY (22),
            // but can also be used for modern Ed25519 (27)
            if (algorithmId == PublicKeyAlgorithmTags.EDDSA_LEGACY)
            {
                // card emits Ed25519 support for curve 1.3.101.112,
                // but legacy Ed25519 keys carry OID 1.3.6.1.4.1.11591.15.1 (GNU)
                if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY &&
                        keyCurve.equals(GNUObjectIdentifiers.Ed25519) &&
                        curve.equals(EdECObjectIdentifiers.id_Ed25519))
                {
                    // Manually match GNU Ed25519 to EdEC Ed25519
                    return true;
                }

                // Modern Ed25519 key (27)
                // Legacy Ed25519 (22) ~= Ed25519 (27)
                if (keyAlgorithm == PublicKeyAlgorithmTags.Ed25519)
                {
                    // modern Ed25519 keys carry OID 1.3.101.112
                    if (curve.equals(keyCurve))
                    {
                        return true;
                    }
                }
            }

            // Card advertises ECDH support
            if (algorithmId == PublicKeyAlgorithmTags.ECDH)
            {
                // Modern X25519 keys (25) can be used with the card
                if (keyAlgorithm == PublicKeyAlgorithmTags.X25519)
                {
                    if (curve.equals(keyCurve))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private ASN1ObjectIdentifier getKeyCurveOID(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            BCPGKey pubKey = key.getPGPPublicKey().getPublicKeyPacket().getKey();
            if (pubKey instanceof ECPublicBCPGKey)
            {
                ECPublicBCPGKey ecPubKey = (ECPublicBCPGKey) key.getPGPPublicKey().getPublicKeyPacket().getKey();
                return ecPubKey.getCurveOID();
            }
            else if (pubKey instanceof X25519PublicBCPGKey)
            {
                return CryptlibObjectIdentifiers.curvey25519;
            }
            else if (pubKey instanceof Ed25519PublicBCPGKey)
            {
                return EdECObjectIdentifiers.id_Ed25519;
            }
            throw new IllegalArgumentException("unknown key type: " + pubKey.getClass().getName());
        }

        @Override
        public String toString()
        {
            return "Ec{algorithmId=" + algorithmId + ", curve=" + curve + '}';
        }
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        for (Algorithm a : algorithms)
        {
            sb.append(a.toString());
            sb.append("\n");
        }
        return sb.toString();
    }
}
