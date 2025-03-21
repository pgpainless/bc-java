package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSequenceParser;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.PKCS12Util;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKPKCS12StoreParameter;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercise the various key stores, making sure we at least get back what we put in!
 * <p>
 * This tests both the PKCS12 key store.
 */
public class PKCS12StoreTest
    extends SimpleTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    static char[] passwd = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

    //
    // pkcs-12 pfx-pdu
    //
    byte[] pkcs12 = Base64.decode(
        "MIACAQMwgAYJKoZIhvcNAQcBoIAkgAQBMAQBgAQBMAQBgAQBBgQBCQQJKoZI"
            + "hvcNAQcBBAGgBAGABAEkBAGABAEEBAEBBAEwBAEEBAEDBAOCAzQEAQQEAQEE"
            + "ATAEAQQEAQMEA4IDMAQBBAQBAQQBBgQBBAQBAQQBCwQBBAQBCwQLKoZIhvcN"
            + "AQwKAQIEAQQEAQEEAaAEAQQEAQMEA4ICpQQBBAQBAQQBMAQBBAQBAwQDggKh"
            + "BAEEBAEBBAEwBAEEBAEBBAEbBAEEBAEBBAEGBAEEBAEBBAEKBAEEBAEKBAoq"
            + "hkiG9w0BDAEDBAEEBAEPBA8wDQQIoagiwNZPJR4CAQEEAQQEAQEEAQQEAQQE"
            + "AQMEA4ICgAQBBAQDggKABIICgEPG0XlhMFyrs4ZWDrvEzl51ICfXd6K2ql2l"
            + "nnxhszUbigtSj6x49VEx4PfOB9fQFeidc5L5An+nKp646NBMIY0UwXGs8BLQ"
            + "au59jtOs987+l7QYIvl6fdGUIuLPhVSnZZDyqD+HQjU/0/ccKFHRif4tlEQq"
            + "aErvZbFeH0pg4ijf1HfgX6gBJGRKdO+msa4qKGnZdHCSLZehyyxvxAmURetg"
            + "yhtEl7RmedTB+4TDs7atekqxkNlD9tfwDUX6sb0IH6qbEA6P/DlVMdaD54Cl"
            + "QDxRzOfIIjklZhv5OMFWtPK0aYPcqyxzLpw1qRAyoTVXpidkj/hpIpgCVBP/"
            + "k5s2+WdGbLgA/4/zSrF6feRCE5llzM2IGxiHVq4oPzzngl3R+Fi5VCPDMcuW"
            + "NRuIOzJA+RNV2NPOE/P3knThDnwiImq+rfxmvZ1u6T06s20RmWK6cxp7fTEw"
            + "lQ9BOsv+mmyV8dr6cYJq4IlRzHdFOyEUBDwfHThyribNKKobO50xh2f93xYj"
            + "Rn5UMOQBJIe3b7OKZt5HOIMrJSZO02IZgvImi9yQWi96PnWa419D1cAsLWvM"
            + "xiN0HqZMbDFfxVM2BZmsxiexLhkHWKwLqfQDzRjJfmVww8fnXpWZhFXKyut9"
            + "gMGEyCNoba4RU3QI/wHKWYaK74qtJpsucuLWBH6UcsHsCry6VZkwRxWwC0lb"
            + "/F3Bm5UKHax5n9JHJ2amQm9zW3WJ0S5stpPObfmg5ArhbPY+pVOsTqBRlop1"
            + "bYJLD/X8Qbs468Bwzej0FhoEU59ZxFrbjLSBsMUYrVrwD83JE9kEazMLVchc"
            + "uCB9WT1g0hxYb7VA0BhOrWhL8F5ZH72RMCYLPI0EAQQEAQEEATEEAQQEAQEE"
            + "AXgEAQQEAQEEATAEAQQEAQEEAVEEAQQEAQEEAQYEAQQEAQEEAQkEAQQEAQkE"
            + "CSqGSIb3DQEJFAQBBAQBAQQBMQQBBAQBAQQBRAQBBAQBAQQBHgQBBAQBAQQB"
            + "QgQBBAQBQgRCAEQAYQB2AGkAZAAgAEcALgAgAEgAbwBvAGsAJwBzACAAVgBl"
            + "AHIAaQBTAGkAZwBuACwAIABJAG4AYwAuACAASQBEBAEEBAEBBAEwBAEEBAEB"
            + "BAEjBAEEBAEBBAEGBAEEBAEBBAEJBAEEBAEJBAkqhkiG9w0BCRUEAQQEAQEE"
            + "ATEEAQQEAQEEARYEAQQEAQEEAQQEAQQEAQEEARQEAQQEARQEFKEcMJ798oZL"
            + "FkH0OnpbUBnrTLgWBAIAAAQCAAAEAgAABAEwBAGABAEGBAEJBAkqhkiG9w0B"
            + "BwYEAaAEAYAEATAEAYAEAQIEAQEEAQAEATAEAYAEAQYEAQkECSqGSIb3DQEH"
            + "AQQBMAQBGwQBBgQBCgQKKoZIhvcNAQwBBgQPMA0ECEE7euvmxxwYAgEBBAGg"
            + "BAGABAEEBAEIBAgQIWDGlBWxnwQBBAQBCAQI2WsMhavhSCcEAQQEAQgECPol"
            + "uHJy9bm/BAEEBAEQBBCiRxtllKXkJS2anKD2q3FHBAEEBAEIBAjKy6BRFysf"
            + "7gQBBAQDggMwBIIDMJWRGu2ZLZild3oz7UBdpBDUVMOA6eSoWiRIfVTo4++l"
            + "RUBm8TpmmGrVkV32PEoLkoV+reqlyWCvqqSjRzi3epQiVwPQ6PV+ccLqxDhV"
            + "pGWDRQ5UttDBC2+u4fUQVZi2Z1i1g2tsk6SzB3MKUCrjoWKvaDUUwXo5k9Vz"
            + "qSLWCLTZCjs3RaY+jg3NbLZYtfMDdYovhCU2jMYV9adJ8MxxmJRz+zPWAJph"
            + "LH8hhfkKG+wJOSszqk9BqGZUa/mnZyzeQSMTEFga1ZB/kt2e8SZFWrTZEBgJ"
            + "oszsL5MObbwMDowNurnZsnS+Mf7xi01LeG0VT1fjd6rn9BzVwuMwhoqyoCNo"
            + "ziUqSUyLEwnGTYYpvXLxzhNiYzW8546KdoEKDkEjhfYsc4XqSjm9NYy/BW/M"
            + "qR+aL92j8hqnkrWkrWyvocUe3mWaiqt7/oOzNZiMTcV2dgjjh9HfnjSHjFGe"
            + "CVhnEWzV7dQIVyc/qvNzOuND8X5IyJ28xb6a/i1vScwGuo/UDgPAaMjGw28f"
            + "siOZBShzde0Kj82y8NilfYLHHeIGRW+N/grUFWhW25mAcBReXDd5JwOqM/eF"
            + "y+4+zBzlO84ws88T1pkSifwtMldglN0APwr4hvUH0swfiqQOWtwyeM4t+bHd"
            + "5buAlXOkSeF5rrLzZ2/Lx+JJmI2pJ/CQx3ej3bxPlx/BmarUGAxaI4le5go4"
            + "KNfs4GV8U+dbEHQz+yDYL+ksYNs1eb+DjI2khbl28jhoeAFKBtu2gGOL5M9M"
            + "CIP/JDOCHimu1YZRuOTAf6WISnG/0Ri3pYZsgQ0i4cXj+WfYwYVjhKX5AcDj"
            + "UKnc4/Cxp+TbbgZqEKRcYVb2q0kOAxkeaNo3WCm+qvUYrwAmKp4nVB+/24rK"
            + "khHiyYJQsETxtOEyvJkVxAS01djY4amuJ4jL0sYnXIhW3Ag93eavbzksGT7W"
            + "Fg1ywpr1x1xpXWIIuVt1k4e+g9fy7Yx7rx0IK1qCSjNwU3QPWbaef1rp0Q/X"
            + "P9IVXYkqo1g/T3SyXqrbZLO+sDjiG4IT3z3fJJqt81sRSVT0QN1ND8l93BG4"
            + "QKzghYw8sZ4FwKPtLky1dDcVTgQBBAQBCAQIK/85VMKWDWYEAQQEAQgECGsO"
            + "Q85CcFwPBAEEBAEIBAhaup6ot9XnQAQBBAQCgaAEgaCeCMadSm5fkLfhErYQ"
            + "DgePZl/rrjP9FQ3VJZ13XrjTSjTRknAbXi0DEu2tvAbmCf0sdoVNuZIZ92W0"
            + "iyaa2/A3RHA2RLPNQz5meTi1RE2N361yR0q181dC3ztkkJ8PLyd74nCtgPUX"
            + "0JlsvLRrdSjPBpBQ14GiM8VjqeIY7EVFy3vte6IbPzodxaviuSc70iXM4Yko"
            + "fQq6oaSjNBFRqkHrBAEEBAEIBAjlIvOf8SnfugQBBAQBCAQIutCF3Jovvl0E"
            + "AQQEAQgECO7jxbucdp/3BAEEBAEIBAidxK3XDLj+BwQBBAQBCAQI3m/HMbd3"
            + "TwwEAQQEA4ICOASCAjgtoCiMfTkjpCRuMhF5gNLRBiNv+xjg6GvZftR12qiJ"
            + "dLeCERI5bvXbh9GD6U+DjTUfhEab/37TbiI7VOFzsI/R137sYy9Tbnu7qkSx"
            + "u0bTvyXSSmio6sMRiWIcakmDbv+TDWR/xgtj7+7C6p+1jfUGXn/RjB3vlyjL"
            + "Q9lFe5F84qkZjnADo66p9gor2a48fgGm/nkABIUeyzFWCiTp9v6FEzuBfeuP"
            + "T9qoKSnCitaXRCru5qekF6L5LJHLNXLtIMSrbO0bS3hZK58FZAUVMaqawesJ"
            + "e/sVfQip9x/aFQ6U3KlSpJkmZK4TAqp9jIfxBC8CclbuwmoXPMomiCH57ykr"
            + "vkFHOGcxRcCxax5HySCwSyPDr8I4+6Kocty61i/1Xr4xJjb+3oyFStIpB24x"
            + "+ALb0Mz6mUa1ls76o+iQv0VM2YFwnx+TC8KC1+O4cNOE/gKeh0ircenVX83h"
            + "GNez8C5Ltg81g6p9HqZPc2pkwsneX2sJ4jMsjDhewV7TyyS3x3Uy3vTpZPek"
            + "VdjYeVIcgAz8VLJOpsIjyHMB57AyT7Yj87hVVy//VODnE1T88tRXZb+D+fCg"
            + "lj2weQ/bZtFzDX0ReiEQP6+yklGah59omeklIy9wctGV1o9GNZnGBSLvQ5NI"
            + "61e9zmQTJD2iDjihvQA/6+edKswCjGRX6rMjRWXT5Jv436l75DVoUj09tgR9"
            + "ytXSathCjQUL9MNXzUMtr7mgEUPETjM/kYBR7CNrsc+gWTWHYaSWuqKVBAEE"
            + "BAEIBAh6slfZ6iqkqwQBBAQBCAQI9McJKl5a+UwEAQQEATgEOBelrmiYMay3"
            + "q0OW2x2a8QQodYqdUs1TCUU4JhfFGFRy+g3yU1cP/9ZSI8gcI4skdPc31cFG"
            + "grP7BAEEBAEIBAhzv/wSV+RBJQQBBAQBCAQI837ImVqqlr4EAQQEAQgECGeU"
            + "gjULLnylBAEEBAEIBAjD3P4hlSBCvQQBBAQBCAQISP/qivIzf50EAQQEAQgE"
            + "CKIDMX9PKxICBAEEBAOCBOgEggTocP5VVT1vWvpAV6koZupKN1btJ3C01dR6"
            + "16g1zJ5FK5xL1PTdA0r6iAwVtgYdxQYnU8tht3bkNXdPJC1BdsC9oTkBg9Nr"
            + "dqlF5cCzXWIezcR3ObjGLpXu49SAHvChH4emT5rytv81MYxZ7bGmlQfp8BNa"
            + "0cMZz05A56LXw//WWDEzZcbKSk4tCsfMXBdGk/ngs7aILZ4FGM620PBPtD92"
            + "pz2Ui/tUZqtQ0WKdLzwga1E/rl02a/x78/OdlVRNeaIYWJWLmLavX98w0PhY"
            + "ha3Tbj/fqq+H3ua6Vv2Ff4VeXazkXpp4tTiqUxhc6aAGiRYckwZaP7OPSbos"
            + "RKFlRLVofSGu1IVSKO+7faxV4IrVaAAzqRwLGkpJZLV7NkzkU1BwgvsAZAI4"
            + "WClPDF228ygbhLwrSN2NK0s+5bKhTCNAR/LCUf3k7uip3ZSe18IwEkUMWiaZ"
            + "ayktcTYn2ZjmfIfV7wIxHgWPkP1DeB+RMS7VZe9zEgJKOA16L+9SNBwJSSs9"
            + "5Sb1+nmhquZmnAltsXMgwOrR12JLIgdfyyqGcNq997U0/KuHybqBVDVu0Fyr"
            + "6O+q5oRmQZq6rju7h+Hb/ZUqRxRoTTSPjGD4Cu9vUqkoNVgwYOT+88FIMYun"
            + "g9eChhio2kwPYwU/9BNGGzh+hAvAKcUpO016mGLImYin+FpQxodJXfpNCFpG"
            + "4v4HhIwKh71OOfL6ocM/518dYwuU4Ds2/JrDhYYFsn+KprLftjrnTBnSsfYS"
            + "t68b+Xr16qv9r6sseEkXbsaNbrGiZAhfHEVBOxQ4lchHrMp4zpduxG4crmpc"
            + "+Jy4SadvS0uaJvADgI03DpsDYffUdriECUqAfOg/Hr7HHyr6Q9XMo1GfIarz"
            + "eUHBgi1Ny0nDTWkdb7I3bIajG+Unr3KfK6dZz5Lb3g5NeclU5zintB1045Jr"
            + "j9fvGGk0/2lG0n17QViBiOzGs2poTlhn7YxmiskwlkRKVafxPZNPxKILpN9s"
            + "YaWGz93qER/pGMJarGJxu8sFi3+yt6FZ4pVPkvKE8JZMEPBBrmH41batS3sw"
            + "sfnJ5CicAkwd8bluQpoc6qQd81HdNpS6u7djaRSDwPtYnZWu/8Hhj4DXisje"
            + "FJBAjQdn2nK4MV7WKVwr+mNcVgOdc5IuOZbRLOfc3Sff6kYVuQFfcCGgAFpd"
            + "nbprF/FnYXR/rghWE7fT1gfzSMNv+z5UjZ5Rtg1S/IQfUM/P7t0UqQ01/w58"
            + "bTlMGihTxHiJ4Qf3o5GUzNmAyryLvID+nOFqxpr5es6kqSN4GPRHsmUIpB9t"
            + "f9Nw952vhsXI9uVkhQap3JvmdAKJaIyDz6Qi7JBZvhxpghVIDh73BQTaAFP9"
            + "5GUcPbYOYJzKaU5MeYEsorGoanSqPDeKDeZxjxJD4xFsqJCoutyssqIxnXUN"
            + "Y3Uojbz26IJOhqIBLaUn6QVFX79buWYjJ5ZkDS7D8kq6DZeqZclt5711AO5U"
            + "uz/eDSrx3d4iVHR+kSeopxFKsrK+KCH3CbBUMIFGX/GE9WPhDWCtjjNKEe8W"
            + "PinQtxvv8MlqGXtv3v7ObJ2BmfIfLD0rh3EB5WuRNKL7Ssxaq14KZGEBvc7G"
            + "Fx7jXLOW6ZV3SH+C3deJGlKM2kVhDdIVjjODvQzD8qw8a/ZKqDO5hGGKUTGD"
            + "Psdd7O/k/Wfn+XdE+YuKIhcEAQQEAQgECJJCZNJdIshRBAEEBAEIBAiGGrlG"
            + "HlKwrAQBBAQBCAQIkdvKinJYjJcEAQQEAUAEQBGiIgN/s1bvPQr+p1aQNh/X"
            + "UQFmay6Vm5HIvPhoNrX86gmMjr6/sg28/WCRtSfyuYjwQkK91n7MwFLOBaU3"
            + "RrsEAQQEAQgECLRqESFR50+zBAEEBAEIBAguqbAEWMTiPwQBBAQBGAQYKzUv"
            + "EetQEAe3cXEGlSsY4a/MNTbzu1WbBAEEBAEIBAiVpOv1dOWZ1AQCAAAEAgAA"
            + "BAIAAAQCAAAEAgAABAIAAAAAAAAAADA1MCEwCQYFKw4DAhoFAAQUvMkeVqe6"
            + "D4UmMHGEQwcb8O7ZwhgEEGiX9DeqtRwQnVi+iY/6Re8AAA==");

    byte[] certUTF = Base64.decode(
        "MIIGVQIBAzCCBg8GCSqGSIb3DQEHAaCCBgAEggX8MIIF+DCCAsUGCSqGSIb3"
            + "DQEHAaCCArYEggKyMIICrjCCAqoGCyqGSIb3DQEMCgEDoIIChTCCAoEGCiqG"
            + "SIb3DQEJFgGgggJxBIICbTCCAmkwggHSoAMCAQICAQcwDQYJKoZIhvcNAQEF"
            + "BQAwOTEPMA0GA1UEBxMGTGV1dmVuMRkwFwYDVQQKExBVdGltYWNvIFN1YiBD"
            + "QSAyMQswCQYDVQQGEwJCRTAeFw05OTEyMzEyMzAwMDBaFw0xOTEyMzEyMzAw"
            + "MDBaMFcxCzAJBgNVBAYTAkJFMQ8wDQYDVQQHEwZIYWFjaHQxEDAOBgNVBAoT"
            + "B1V0aW1hY28xDDAKBgNVBAsMA1ImRDEXMBUGA1UEAxMOR2VlcnQgRGUgUHJp"
            + "bnMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANYGIyhTn/p0IA41ElLD"
            + "fZ44PS88AAcDCiOd2DIMLck56ea+5nhI0JLyz1XgPHecc8SLFdl7vSIBA0eb"
            + "tm/A7WIqIp0lcvgoyQ0qsak/dvzs+xw6r2xLCVogku4+/To6UebtfRsukXNI"
            + "ckP5lWV/Ui4l+XvGdmENlEE9/BvOZIvLAgMBAAGjYzBhMBEGA1UdIwQKMAiA"
            + "BlN1YkNBMjAQBgNVHQ4ECQQHVXNlcklEMjAOBgNVHQ8BAf8EBAMCBLAwGQYD"
            + "VR0RBBIwEIEOVXNlcklEMkB1dGkuYmUwDwYDVR0TAQH/BAUwAwEBADANBgkq"
            + "hkiG9w0BAQUFAAOBgQACS7iLLgMV4O5gFdriI7dqX55l7Qn6HiRNxlSH2kCX"
            + "41X82gae4MHFc41qqsC4qm6KZWi1yvTN9XgSBCXTaw1SXGTK7SuNdoYh6ufC"
            + "KuAwy5lsaetyARDksRiOIrNV9j+MRIjJMjPNg+S+ysIHTWZo2NTUuVuZ01D2"
            + "jDtYPhcDFDESMBAGCSqGSIb3DQEJFTEDBAE3MIIDKwYJKoZIhvcNAQcGoIID"
            + "HDCCAxgCAQAwggMRBgkqhkiG9w0BBwEwKAYKKoZIhvcNAQwBAzAaBBS5KxQC"
            + "BMuZ1To+yed2j/TT45td6gICCACAggLYxQS+fu7W2sLQTkslI0EoNxLoH/WO"
            + "L8NgiIgZ5temV3mgC2q0MxjVVq+SCvG89ZSTfptxOaSmYV772irFdzlrtotZ"
            + "wmYk1axuFDYQ1gH0M6i9FWuhOnbk7qHclmOroXqrrbP6g3IsjwztH0+iwBCg"
            + "39f63V0rr8DHiu7zZ2hBkU4/RHEsXLjaCBVNTUSssWhVLisLh2sqBJccPC2E"
            + "1lw4c4WrshGQ+syLGG38ttFgXT1c+xYNpUKqJiJTLVouOH9kK3nH1hPRHKMN"
            + "9CucBdUzibvkcRk1L53F3MfvjhCSNeWEmd9PKN+FtUtzRWQG3L84VGTM37Ws"
            + "YcxaDwDFGcw3u1W8WFsCCkjpZecKN8P2Kp/ai/iugcXY77bYwAwpETDvQFvD"
            + "nnL9oGi03HYdfeiXglC7x7dlojvnpkXDbE0nJiFwhe8Mxpx8GVlGHtP+siXg"
            + "tklubg1eTCSoG9m1rsBJM717ZHXUGf32HNun2dn4vOWGocgBmokZ46KKMb9v"
            + "reT39JTxi8Jlp+2cYb6Qr/oBzudR+D4iAiiVhhhEbJKPNHa61YyxF810fNI2"
            + "GWlNIyN3KcI8XU6WJutm/0H3X8Y+iCSWrJ2exUktj8GiqNQ6Yx0YgEk9HI7W"
            + "t9UVTIsPCgCqrV4SWCOPf6so1JqnpvlPvvNyNxSsAJ7DaJx1+oD2QQfhowk/"
            + "bygkKnRo5Y15ThrTsIyQKsJHTIVy+6K5uFZnlT1DGV3DcNpuk3AY26hrAzWO"
            + "TuWXsULZe7M6h6U2hTT/eplZ/mwHlXdF1VErIuusaCdkSI0doY4/Q223H40L"
            + "BNU3pTezl41PLceSll00WGVr2MunlNeXKnXDJW06lnfs9BmnpV2+Lkfmf30W"
            + "Pn4RKJQc+3D3SV4fCoQLIGrKiZLFfEdGJcMlySr+dJYcEtoZPuo6i/hb5xot"
            + "le63h65ihNtXlEDrNpYSQqnfhjOzk5/+ZvYEcOtDObEwPTAhMAkGBSsOAwIa"
            + "BQAEFMIeDI9l2Da24mtA1fbQIPc6+4dUBBQ8a4lD7j1CA1vRLhdEgPM+5hpD"
            + "RgICCAA=");

    byte[] pkcs12noFriendly = Base64.decode(
        "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCBAAwgDCABgkqhkiG9w0BBwGggCSA"
            + "BIICvjCCArowggK2BgsqhkiG9w0BDAoBAqCCAqUwggKhMBsGCiqGSIb3DQEM"
            + "AQMwDQQIyJDupEHvySECAQEEggKAupvM7RuZL3G4qNeJM3afElt03TVfynRT"
            + "xUxAZOfx+zekHJTlnEuHJ+a16cOV6dQUgYfyMw1xcq4E+l59rVeMX9V3Zr0K"
            + "tsMN9VYB/9zn62Kw6LQnY0rMlWYf4bt9Ut5ysq0hE5t9FL+NZ5FbFdWBOKsj"
            + "/3oC6eNXOkOFyrY2haPJtD1hVHUosrlC0ffecV0YxPDsReeyx0R4CiYZpAUy"
            + "ZD7rkxL+mSX7zTsShRiga2Q/NEhC1KZpbhO/qbyOgvH0r7CRumSMvijzDgaV"
            + "IGqtrIZ2E2k5kscjcuFTW0x3OZTLAW/UnAh4JXJzC6isbdiWuswbAEBHifUC"
            + "rk2f+bDJKe2gkH67J2K0yDQ3YSSibpjDX/bVfbtfmOoggK9MKQwqEeE0nbYE"
            + "jzInH2OK5jPtmwppjmVA7i3Uk25w2+z7b/suUbft9hPCNjxFvzdbyCcXK4Vv"
            + "xAgEbVWnIkvOQNbyaQi+DEF/4P26GwgJgXuJpMBn0zzsSZSIDLNl8eJHoKp2"
            + "ZXknTi0SZkLaYlBxZlNhFoyXLfvQd6TI2aR5aCVqg1aZMBXyOWfz5t0JTVX8"
            + "HTIcdXKis91iEsLB7vjcxIOASTAjKARr5tRp6OvaVterAyDOn2awYQJLLic5"
            + "pQfditRAlsLkTxlDdu0/QBMXSPptO8g3R+dS7ntvCjXgZZyxpOeKkssS2l5v"
            + "/B2EsfKmYA9hU4aBdW1S9o/PcF1wpVqABd8664TGJ77tCAkbdHe0VJ3Bop2X"
            + "lNxlWeEeD0v0QUZLqkJoMEwi5SUE6HAWjbqGhRuHyey9E+UsdCVnQ8AxXQzL"
            + "2UKOmIrXc6R25GsLPCysXuXPRFBB2Tul0V3re3hPcAAAAAAAADCABgkqhkiG"
            + "9w0BBwaggDCAAgEAMIAGCSqGSIb3DQEHATAbBgoqhkiG9w0BDAEGMA0ECDXn"
            + "UZu6xckzAgEBoIAEggTYQMbzAoGnRVJMbCaJJUYgaARJ4zMfxt2e12H4pX/e"
            + "vnZrR1eKAMck5c2vJoEasr0i2VUcAcK12AntVIEnBwuRBcA2WrZnC28WR+O7"
            + "rLdu9ymG2V3zmk66aTizaB6rcHAzs2lD74n+/zJhZNaDMBfu9LzAdWb/u6Rb"
            + "AThmbw764Zyv9802pET6xrB8ureffgyvQAdlcGHM+yxaOV3ZEtS0cp7i+pb/"
            + "NTiET4jAFoO1tbBrWGJSRrMKvx4ZREppMhG3e/pYglfMFl+1ejbDsOvEUKSt"
            + "H+MVrgDgAv4NsUtNmBu+BIIEAIOCjrBSK3brtV0NZOWsa6hZSSGBhflbEY8s"
            + "U1bDsgZIW4ZaJJvSYEXLmiWSBOgq9VxojMfjowY+zj6ePJJMyI3E7AcFa+on"
            + "zZjeKxkKypER+TtpBeraqUfgf01b6olH8L2i4+1yotCQ0PS+15qRYPK6D+d3"
            + "S+R4veOA6wEsNRijVcB3oQsBCi0FVdf+6MVDvjNzBCZXj0heVi+x0EE106Sz"
            + "B3HaDbB/KNHMPZvvs3J3z2lWLj5w7YZ9eVmrVJKsgG2HRKxtt2IQquRj4BkS"
            + "upFnMTBVgWxXgwXycauC9bgYZurs+DbijqhHfWpUrttDfavsP8aX6+i3gabK"
            + "DH4LQRL7xrTcKkcUHxOTcPHLgDPhi+RevkV+BX9tdajbk4tqw1d+0wOkf1pW"
            + "aTG8fUp0lUpra7EJ0lGy8t/MB3NEk/5tLk9qA2nsKKdNoEdZWiEBE0fMrH1o"
            + "tWJDew3VhspT+Lkor2dLN5ydjcr3wkb76OETPeMxS91onNj5mrAMUBt66vb6"
            + "Gx4CL8FTRNZ/l8Kzngzdv9PmmKPTIXbhYbn3XRGg3od2tC/oVfsqYlGAMgFO"
            + "STt+BZ1BR9Phyi4jsiy8R0seCEDRWYQLbwgwVj0V8Rx9VptqRoCnB4XhGJoJ"
            + "TdAz/MT7KOSxIh2F2FymTJpyImcV6X4Kcj9iY0AZQ4zj712g4yMR6xKGzRu6"
            + "oIBDkFW2bdA3Lb9ePpo5GFtNyA7IbggIko6VOeeOKxaq9nALS2gsZc1yaYtp"
            + "aKL8kB+dVTCXiLgQniO6eMzgonsuwFnG+42XM1vhEpAvFzeJRC0CYzebEK9n"
            + "nGXKCPoqPFuw3gcPMn57NCZJ8MjT/p0wANIEm6AsgqrdFKwTRVJ1ytB/X9Ri"
            + "ysmjMBs9zbFKjU9jVDg1vGBNtb7YnYg9IrYHa3e4yTu2wUJKGP2XWHVgjDR7"
            + "6RtzlO4ljw0kkSMMEDle2ZbGZ6lVXbFwV0wPNPmGA6+XGJRxcddTnrM6R/41"
            + "zqksFLgoNL2BdofMXwv7SzxGyvFhHdRRdBZ5dKj2K9OfXakEcm/asZGu87u8"
            + "y9m7Cckw8ilSNPMdvYiFRoThICx9NiwYl1IIKGcWlb9p6RAx6XNSkY6ZZ6pE"
            + "Vla1E26rbd7is1ssSeqxLXXV9anuG5HDwMIt+CIbD8fZmNTcWMzZRiaFajvR"
            + "gXdyTu/UhVdhiQPF+lrxp4odgF0cXrpcGaKvOtPq04F4ad3O5EkSGucI210Q"
            + "pR/jQs07Yp5xDPzsXAb8naHb84FvK1iONAEjWbfhDxqtH7KGrBbW4KEzJrv3"
            + "B8GLDp+wOAFjGEdGDPkOx3y2L2HuI1XiS9LwL+psCily/A96OiUyRU8yEz4A"
            + "AAAAAAAAAAAEAwAAAAAAAAAAADAtMCEwCQYFKw4DAhoFAAQU1NQjgVRH6Vg3"
            + "tTy3wnQisALy9aYECKiM2gZrLi+fAAA=");

    static char[] noFriendlyPassword = "sschette12".toCharArray();

    byte[] pkcs12StorageIssue = Base64.decode(
        "MIIO8QIBAzCCDrEGCSqGSIb3DQEHAaCCDqIEgg6eMIIOmjCCBBMGCSqGSIb3"
            + "DQEHAaCCBAQEggQAMIID/DCCA/gGCyqGSIb3DQEMCgECoIICtjCCArIwHAYK"
            + "KoZIhvcNAQwBAzAOBAgURJ+/5hA2pgICB9AEggKQYZ4POE8clgH9Bjd1XO8m"
            + "sr6NiRBiA08CllHSOn2RzyAgHTa+cKaWrEVVJ9mCd9XveSUCoBF9E1C3jSl0"
            + "XIqLNgYd6mWK9BpeMRImM/5crjy///K4ab9kymzkc5qc0pIpdCQCZ04YmtFP"
            + "B80VCgyaoh2xoxqgjBCIgdSg5XdepdA5nXkG9EsQ1oVUyCykv20lKgKKRseG"
            + "Jo23AX8YUYR7ANqP2gz9lvlX6RBczuoZ62ujopUexiQgt5SZx97sgo3o/b/C"
            + "px17A2L4wLdeAYCMCsZhC2UeaqnZCHSsvnPZfRGiuSEGbV5gHLmXszLDaEdQ"
            + "Bo873GTpKTTzBfRFzNCtYtZRqh2AUsInWZWQUcCeX6Ogwa0wTonkp18/tqsh"
            + "Fj1fVpnsRmjJTTXFxkPtUw5GPJnDAM0t1xqV7kOjN76XnZrMyk2azQ1Mf3Hn"
            + "sGpF+VRGH6JtxbM0Jm5zD9uHcmkSfNR3tP/+vHOB1mkIR9tD2cHvBg7pAlPD"
            + "RfDVWynhS+UBNlQ0SEM/pgR7PytRSUoKc/hhe3N8VerF7VL3BwWfBLlZFYZH"
            + "FvPQg4coxF7+We7nrSQfXvdVBP9Zf0PTdf3pbZelGCPVjOzbzY/o/cB23IwC"
            + "ONxlY8SC1nJDXrPZ5sY51cg/qUqor056YqipRlI6I+FoTMmMDKPAiV1V5ibo"
            + "DNQJkyv/CAbTX4+oFlxgddTwYcPZgd/GoGjiP9yBHHdRISatHwMcM06CzXJS"
            + "s3MhzXWD4aNxvvSpXAngDLdlB7cm4ja2klmMzL7IuxzLXFQFFvYf7IF5I1pC"
            + "YZOmTlJgp0efL9bHjuHFnh0S0lPtlGDOjJ/4YpWvSKDplcPiXhaFVjsUtclE"
            + "oxCC5xppRm8QWS8xggEtMA0GCSsGAQQBgjcRAjEAMBMGCSqGSIb3DQEJFTEG"
            + "BAQBAAAAMGkGCSsGAQQBgjcRATFcHloATQBpAGMAcgBvAHMAbwBmAHQAIABS"
            + "AFMAQQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAA"
            + "aABpAGMAIABQAHIAbwB2AGkAZABlAHIwgZsGCSqGSIb3DQEJFDGBjR6BigA3"
            + "AGQAZQBmADUAYgA0ADMANgBjAGEAYgBkADAAMAAyAGQAZAAyADkAMAAzAGIA"
            + "MQA2ADgANgBjADcAOQA0ADgAXwA0ADYAZgAyADYAZgBkADQALQA4ADEAMgBk"
            + "AC0ANABlAGYAYgAtADgAMAA4ADgALQA0ADUAYQBiADkAMQA5ADEAMAA3AGMA"
            + "YzCCCn8GCSqGSIb3DQEHBqCCCnAwggpsAgEAMIIKZQYJKoZIhvcNAQcBMBwG"
            + "CiqGSIb3DQEMAQYwDgQIbr2xdnQ9inMCAgfQgIIKOHg9VKz+jlM+3abi3cp6"
            + "/XMathxDSEJLrxJs6j5DAVX17S4sw1Q/1pptjdMdd8QtTfUB6JpfgJ5Kpn+h"
            + "gZMf6M8wWue0U/RZN0D9w7o+2n+X3ItdEXu80eJVDOm7I2p8qiXtijbMbXRL"
            + "Cup1lgfPM5uv2D63/hmWRXLeG8eySrJnKENngpM559V8TI2JcTUBy1ZP3kcH"
            + "KbcJ/tVPnIIe4qguxfsTmDtAQviGvWUohbt+RGFmtqfgntK7o6b+S8uRSwEs"
            + "fOU/pnVE9M1ugtNJZI/xeGJq6umZWXA/OrAcK7feWUwqRvfivDGQJEoggByd"
            + "4/g92PhK1JGkwlCb1HdfhOOKKChowQ4zVvSOm+uBxARGhk2i5uW9I20I0vSJ"
            + "px42O2VFVJweOchfp+wBtSHBKYP1ZXyXWMvOtULClosSeesbYMAwvyBfpYEz"
            + "3rQt/1iZkqDmEisXk8X1aEKG1KSWaSPyb/+6glWikDm+YdQw3Khu7IZt1l/H"
            + "qWGecccel+R9mT4YjRzHlahUYk4U+RNVasVpH1Kxz2j3CZqL+b3jQOwSAPd/"
            + "hKI+S/pjIpBPfiC4WxORAzGZzY2j+a79B70h1DO1D9jGur3vJDbdmGBNgs6d"
            + "nonE1B527SICcGeXY1MtnZCLOPvySih0AvOekbN9x2CJg+Hp9e7A3Fxni53/"
            + "oMLr9wGRRDki72eXCXW98mU8VJofoWYS1/VBLXGf/f+tJ9J02PpzxleqPH9T"
            + "4mE+YHnZId6cqjCXmwvMr2cMw2clDVfvkbAJRE3eZHzL7IWSO8+giXzzrTsl"
            + "VbMuXVkT4oniTN7TSRsBCT3zVVmCy1QL2hPBD6KsVc+bvLgAHRov84FPrI3f"
            + "kY/oJufT36VE34Eu+QjzULlvVsLE3lhjutOerVIGSP//FM4LE99hp214P0JF"
            + "DgBK+3J+ihmFdW8hUXOt6BU8/MBeiroiJMWo1/f/XcduekG2ZsdGv+GNPzXI"
            + "PyHRpCgAgmck1+qoUPXxHRJuNqv223OZ5MN14X7iLl5OZ+f8IWfxUnZeZ9gj"
            + "HNeceElwZ+YOup1CAi3haD9jxRWhZG4NDfB4IYi4Bc/TAkXE3jCPkYEvIbj9"
            + "ExaU1Ts0+lqOOcwRmBoYjVrz0xbtfR/OWlopyrDHbeL5iQcQCW/loYRapWCZ"
            + "E4ekHknpX9yoAwT355vtTkl0VKXeSZHE8jREhN95aY9zCoLYwbTQDTw7qUR5"
            + "UamabLew0oS0XALtuOrfX4OUOZZUstUsGBle/Pw1TE3Bhe1clhrikp0F+Xgb"
            + "Xx90KqxZX/36RMnCMAD7/q+57rV7WXp2Y5tT0AUgyUMjy1F1X/b1olUfqO1u"
            + "rlWIUTl2znmQ3D9uO3W4ytfgGd5DpKcl2w84MBAT9qGwKuQg/UYKbP4K/+4L"
            + "Y1DWCy3utmohQ28IJtlIUkPL1G7lHX1tfq/VA+bRNTJIhMrNn06ZJpuEJHDs"
            + "/ferdlMFt/d6MrwVivmPVYkb8mSbHSiI8jZOFE44sA974depsDyXafFaSsl0"
            + "bVzqOAu0C/n9dIednU0xxxgDF/djdZ/QhbaDIg2VJf11wx0nw9n76B0+eeyu"
            + "QLaapzxCpQNDVOAM9doBb5F1I5pXQHFQqzTNtLmqDC4x0g8IH7asyk5LCglT"
            + "b1pwMqPJOL2vGWKRLhPzT+9OfSpCmYGKytf593hmGmwIgEO13hQrw31F5TYt"
            + "btkbDr+Q5XilOKEczhEM+Ug7YHU7bxkckOAbxu0YeRp/57GdGLokeLJ0dRlQ"
            + "+V2CfQvWJoVC6PS4PUQtjwgK2p/LU10QsEFwM/S621fGq9zGrv7+FPBATRDb"
            + "k4E9D/WaRylnW11ZTrOlTchQkoHcOh0xztlFxU8jzuIuDrPQQWkoqdl6B+yf"
            + "lykRNJKKxwzFiPl40nLC3nEdIzCEvR4r/9QHiWQxAVSc/wQX+an5vakUmSXS"
            + "oLFjgVdY1jmvdsx2r5BQPuOR8ONGmw/muvVSMaHV85brA4uk0lxn00HD9/a0"
            + "A1LCeFkabNLn9wJT8RaJeOSNmFFllLR70OHaoPSb3GyzHpvd1e6aeaimdyVH"
            + "BQWJ6Ufx+HjbOGuOiN46WyE6Q27dnWxx8qF89dKB4T/J0mEXqueiUjAUnnnR"
            + "Cs4zPaX53hmNBdrZGaLs+xNG8xy+iyBUJIWWfQAQjCjfHYlT9nygiUWIbVQq"
            + "RHkGkAN62jsSNLgHvWVzQPNNsYq0U8TPhyyci/vc8MJytujjptcz8FPqUjg2"
            + "TPv34ef9buErsm4vsdEv/8Z+9aDaNex+O3Lo3N0Aw7M5NcntFBHjFY/nBFNZ"
            + "whH5YA4gQ8PLZ5qshlGvb0DFXHV/9zxnsdPkLwH47ERm5IlEAuoaWtZFxg27"
            + "BjLfwU1Opk+ybDSb5WZVZrs7ljsU85p3Vaf3a//yoyr9ITYj15tTXxSPoct0"
            + "fDUy1I6LjJH/+eZXKA1WSda9mDQlRocvJ0IIIlI4weJpTdm8aHIJ8OngCqOF"
            + "TufcSLDM41+nxEK1LqXeAScVy74kVvvqngj6mIrbylrINZOHheEgTXrUWEc0"
            + "uXS8l1YqY6K6Ru5km2jVyWi/ujrDGb6QGShC09oiDYUuUGy4gwJ3XLVX/dR3"
            + "pmMExohTGiVefFP400wVZaxB9g1BQmjSEZxIaW1U1K6fk8Yni8yWB3/L/PuD"
            + "0+OV+98i1sQGaPe35crIpEc7R2XJdngL0Ol1ZuvCIBfy5DQwGIawTtBnjPdi"
            + "hy//QTt/isdu7C5pGaJDkZFMrfxMibr6c3xXr7wwR75sTzPNmS8mquEdLsmG"
            + "h8gTUnB8/K6V11JtUExMqTimTbUw+j8PggpeBelG36breWJIz1O+dmCTGuLM"
            + "x/sK/i8eiUeRvWjqYpq5DYt4URWg2WlcpcKiUxQp07/NMx0svDC+mlQGwMnJ"
            + "8KOJMW1qr3TGEJ/VVKKVn6sXn/RxA+VPofYzhwZByRX87XmNdPeQKC2DHQsW"
            + "6v83dua5gcnv0cv/smXt7Yr/c12i0fbIaQvj3qjtUCDucjARoBey3eCyG5H6"
            + "5VHSsFnPZ2HCTum+jRSw/ENsu/77XU4BIM2fjAfswp7iIr2Xi4OZWKIj6o6q"
            + "+fNgnOJjemDYHAFK+hWxClrG8b+9Eaf21o4zcHkhCfBlYv4d+xcZOIDsDPwI"
            + "sf+4V+CfoBLALsa2K0pXlPplGom/a8h7CjlyaICbWpEDItqwu7NQwdMRCa7i"
            + "yAyM1sVjXUdcZByS1bjOFSeBe7ygAvEl78vApLxqt8Cw11XSsOtmwssecUN/"
            + "pb7iHE4OMyOgsYx9u7rZ2hMyl42n3c29IwDYMumiNqk9cwCBpQTJAQEv4VzO"
            + "QE5xYDBY9SEozni+4f7B7e2Wj/LOGb3vfNVYGNpDczBFxvr2FXTQla0lNYD/"
            + "aePuC++QW4KvwiGL1Zx4Jo0eoDKWYlYj0qiNlQbWfVw+raaaFnlrq+je0W6P"
            + "+BrKZCncho145y+CFKRLZrN5yl/cDxwsePMVhAIMr1DzVhgBXzA3MB8wBwYF"
            + "Kw4DAhoEFN4Cwj9AtArnRbOIAsRhaaoZlTNJBBTIVPqCrloqLns145CWXjb0"
            + "g141BQ==");

    static char[] storagePassword = "pass".toCharArray();

    byte[] pkcs12nopass = Base64.decode(
        "MIIMvgIBAzCCDIQGCSqGSIb3DQEHAaCCDHUEggxxMIIMbTCCCS8GCSqGSIb3"
            + "DQEHBqCCCSAwggkcAgEAMIIJFQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw"
            + "DgQIfnlhuZRR6/YCAggAgIII6DYgeRwq5n9kzvohZ3JuK+fB+9jZ7Or6EGBA"
            + "GDxtBfHmSNUBWJEV/I8wV1zrKKoW/CaoZfA61pyrVZRd/roaqBx/koTFoh/g"
            + "woyyWTRV9gYTXSVqPQgCH+e2dISAa6UGO+/YOWOOwG2X3t8tS+3FduFQFLt5"
            + "cvUP98zENdm57Aef5pKpBSZDLIAoTASfmqwszWABRh2p/wKOHcCQ9Aj2e2vs"
            + "pls/ntIv81MqPuxHttwX8e+3dKWGFrJRztLpCD2aua8VkSsHFsPxEHkezX4O"
            + "6/VCjMCRFGophTS4dgKKtQIhZ9i/ESlr6sGKgIpyG99ALFpNEhtTKe+T3boE"
            + "sEkhGDquSpu4PGz2m0W5sej1DyFkKX4zIbeMDAb1y3O7aP0F+Llo9QSeGsOA"
            + "aCwND3NUAKBMOHzwdyNQcuCGCqY8j5rrSt99A5FMs3UVW3XU6hRCx7JlzO05"
            + "PNCkcPRSnKSNzBhIR5W0qj4PAZnQTfX+wbtUaDLIqsObX4Muh2l3gl+JmdpO"
            + "53U7ILqN8PAPly1eT+fIrUmlMmFhvo6LbTB7B2K728wsA/5wROlud/mOQz4s"
            + "quS288YsnVc9ExSZKodWa3Pqcdb/cgKNJYDxrR6/eBHOj+0RLK/1yTK9ghj7"
            + "IPYHoEqQbw768WK92RjM+RFGlXASkQhR9y4weWj/388uAWMIbQ+R2Zi4nb31"
            + "knjqRPFThysG1bsRL04/9PgysaasfS9KYOeAlLqp+Ar4gJrof5fytBuY+6wm"
            + "/J8eEdNw7VPV1cz/4rhrd2sfJQwDEN/iZoy8rTwe7wozpwZI0lwH11BBbav+"
            + "1AMfI79jjxhqOeo7uxE2NzUmSd05JYI7a94tcRzGQyGEKpGxYCRamzFW23qb"
            + "vG5Hcqi7Tdd7eTxw4c60l/vQLSo38g6ST5yZrK3URLiAtpioPyjrq2jnVfie"
            + "QLsiAHhpHF01+t+OcKv3UjwdEyBmQ34h9klwiG7iwBFXZaPXFCF2Np1TqFVG"
            + "jjBzmB+hRddEiYwN+XGCKB2Cvgc5ZMQ8LG9jQmEKLmOjuumz1ciAVY2qtl1s"
            + "HYSvfNsIAV/gGzHshOVF19JmGtcQt3pMtupoRh+sh8jY2/x5eIKrj2Jx6HPd"
            + "p/6IPUr54j0xSd6j7gWuXMj/eKp/utMNuBzAhkydnhXYedvTDYIj7SyPPIHa"
            + "qtam8rxTDWn2AOxp7OXTgPmo1GU2zW1OLL1D3MFlS+oaRMfhgNrhW+QP5ay6"
            + "ge4QLijpnSM+p0CbFAOClwzgdJV56bBVV09sDqSBXnG9MeEv5nDaH3I+GpPA"
            + "UgDkaI4zT61kaGgk0uNMf3czy2ycoQzTx0iHDTXSdSqvUC1yFza8UG4AYaKz"
            + "14gtSL7StvZtK0Y8oI084BINI1LgrWyrOLj7vkds4WrKhXm21BtM1GbN/pFh"
            + "XI41h+XoD8KnEPqJ36rAgBo1uHqTNJCC7YikDE/dEvq6MkOx+Nug1YZRHEyi"
            + "3AHry5u1HJHtxT34HXBwRXvnstuFhvU6cjc1WY1dJhu1p82TGnx7OBo/QbcM"
            + "8MRrWmWuU5eW4jWbriGNGYfvZy+tHnGwy0bIeqrsHOG6/JwvfmYYXe64sryH"
            + "5Qo96SZtcTJZaNFwuBY+bFUuOWm8YrT1L7Gl2Muf3pEVtNHLeYARBo1jEAym"
            + "Cb4jw0oodZqbPKdyyzUZu69fdTJiQkMUcKDfHJEGK0Li9SvtdqJLiiJs57Tb"
            + "YfOvn+TIuC40ssJFtmtlGCVH/0vtKLWYeW1NYAMzgI/nlhQ7W6Aroh8sZnqv"
            + "SwxeQmRJaVLxiV6YveTKuVlCbqNVLeEtKYAujgnJtPemGCPbwZpwlBw6V+Dz"
            + "oXveOBcUqATztWJeNv7RbU0Mk7k057+DNxXBIU+eHRGquyHQSBXxBbA+OFuu"
            + "4SPfEAyoYed0HEaoKN9lIsBW1xTROI30MZvaJXvPdLsa8izXGPLnTGmoI+fv"
            + "tJ644HtBCCCr3Reu82ZsTSDMxspZ9aa4ro9Oza+R5eULXDhVXedbhJBYiPPo"
            + "J37El5lRqOgu2SEilhhVQq3ZCugsinCaY9P/RtWG4CFnH1IcIT5+/mivB48I"
            + "2XfH6Xq6ziJdj2/r86mhEnz9sKunNvYPBDGlOvI7xucEf9AiEQoTR1xyFDbW"
            + "ljL4BsJqgsHN02LyUzLwqMstwv+/JH1wUuXSK40Kik/N7+jEFW2C+/N8tN7l"
            + "RPKSLaTjxVuTfdv/BH1dkV4iGFgpQrdWkWgkb+VZP9xE2mLz715eIAg13x6+"
            + "n97tc9Hh375xZJqwr3QyYTXWpsK/vx04RThv8p0qMdqKvf3jVQWwnCnoeBv2"
            + "L4h/uisOLY18qka/Y48ttympG+6DpmzXTwD1LycoG2SOWckCMmJhZK40+zr3"
            + "NVmWf6iJtbLGMxI/kzTqbTaOfXc2MroertyM1rILRSpgnJFxJfai5Enspr9b"
            + "SCwlP718jG2lQsnYlw8CuxoZAiaNy4MmC5Y3qNl3hlcggcHeLodyGkSyRsBg"
            + "cEiKSL7JNvqr0X/nUeW28zVxkmQsWlp3KmST8agf+r+sQvw52fXNLdYznGZV"
            + "rJrwgNOoRj0Z70MwTns3s/tCqDEsy5Sv/5dZW2uQEe7/wvmsP2WLu73Rwplg"
            + "1dwi/Uo9lO9dkEzmoIK5wMPCDINxL1K+0Y79q0tIAEMDgaIxmtRpEh8/TEsA"
            + "UwyEErkDsQqgGviH+ePmawJ/yehYHTRfYUgdUflwApJxRx65pDeSYkiYboMU"
            + "8WSAQY2nh/p9hLlS4zbz9dCK2tzVyRkJgqNy/c4IpiHEx2l1iipW9vENglqx"
            + "dYP4uqD8e3OOLjDQKizWx2t1u7GRwoEVQ3d3QzzOvsRcv7h+6vNsmYqE6phe"
            + "wKFZLctpSn21zkyut444ij4sSr1OG68dEXLY0t0mATfTmXXy5GJBsdK/lLfk"
            + "YTIPYYeDMle9aEicDqaKqkZUuYPnVchGp8UFMJ3M0n48OMDdDvpzBLTxxZeW"
            + "cK5v/m3OEo3jgxy9wXfZdz//J3zXXqvX8LpMy1K9X0uCBTz6ERlawviMQhg1"
            + "1okD5zCCAzYGCSqGSIb3DQEHAaCCAycEggMjMIIDHzCCAxsGCyqGSIb3DQEM"
            + "CgECoIICpjCCAqIwHAYKKoZIhvcNAQwBAzAOBAj3QoojTSbZqgICCAAEggKA"
            + "YOSp5XGdnG1pdm9CfvlAaUSHRCOyNLndoUTqteTZjHTEM9bGwNXAx4/R5H2Q"
            + "PnPm5HB/ynVSXX0uKdW6YlbqUyAdV3eqE4X3Nl+K7ZoXmgAFnMr0tveBhT1b"
            + "7rTi0TN4twjJzBTkKcxT8XKjvpVizUxGo+Ss5Wk8FrWLHAiC5dZvgRemtGcM"
            + "w5S09Pwj+qXpjUhX1pB5/63qWPrjVf+Bfmlz4bWcqogGk0i7eg+OdTeWMrW0"
            + "KR9nD1+/uNEyc4FdGtdIPnM+ax0E+vcco0ExQpTXe0xoX4JW7O71d550Wp89"
            + "hAVPNrJA5eUbSWNsuz+38gjUJ+4XaAEhcA7HZIp6ZyxtzSJUoh7oqpRktoxu"
            + "3cSVqVxIqAEqlNn6j0vbKfW91Od5DI5L+BIxY4xqXS7fdwipj9r6qWA8t9QU"
            + "C2r1A+xXpZ4jEh6inHW9qlfACBBrYf8pSDakSR6yTbaA07LExw0IXz5oiQYt"
            + "s7yx231CZlOH88bBmruLOIZsJjeg/lf63zI7Gg4F85QG3RqEJnY2pinLUTP7"
            + "R62VErFZPc2a85r2dbFH1mSQIj/rT1IKe32zIW8xoHC4VwrPkT3bcLFAu2TH"
            + "5k5zSI/gZUKjPDxb2dwLM4pvsj3gJ9vcFZp6BCuLkZc5rd7CyD8HK9PrBLKd"
            + "H3Yngy4A08W4U3XUtIux95WE+5O/UEmSF7fr2vT//DwZArGUpBPq4Bikb8cv"
            + "0wpOwUv8r0DXveeaPsxdipXlt29Ayywcs6KIidLtCaCX6/0u/XtMsGNFS+ah"
            + "OlumTGBFpbLnagvIf0GKNhbg2lTjflACnxIj8d+QWsnrIU1uC1JRRKCnhpi2"
            + "veeWd1m8GUb3aTFiMCMGCSqGSIb3DQEJFTEWBBS9g+Xmq/8B462FWFfaLWd/"
            + "rlFxOTA7BgkqhkiG9w0BCRQxLh4sAEMAZQByAHQAeQBmAGkAawBhAHQAIAB1"
            + "AHoAeQB0AGsAbwB3AG4AaQBrAGEwMTAhMAkGBSsOAwIaBQAEFKJpUOIj0OtI"
            + "j2CPp38YIFBEqvjsBAi8G+yhJe3A/wICCAA=");

    private byte[] gostPfx = Base64.decode(
        "MIIHEgIBAzCCBssGCSqGSIb3DQEHAaCCBrwEgga4MIIGtDCCBYEGCSqGSIb3"
            + "DQEHBqCCBXIwggVuAgEAMIIFZwYJKoZIhvcNAQcBMFUGCSqGSIb3DQEFDTBI"
            + "MCcGCSqGSIb3DQEFDDAaBAi114+lRrpkXAICCAAwCgYGKoUDAgIKBQAwHQYG"
            + "KoUDAgIVMBMECLEIQPMsz/ZZBgcqhQMCAh8BgIIFAbu13yJiW/BnSKYKbtv9"
            + "tDJoTv6l9BVpCCI4tvpzJnMeLBJyVZU4JevcJNii+R1LilVuuB+xc8e7/P4G"
            + "6TILWmnnispr9KPRAbYRfoCJOa59+TYJMur58wwDuYgMapQAFzsvpzyUWi62"
            + "o3uQbbLKO9hQCeJW2L+K9cbg8k33MjXMLpnblKpqmZbHTmBJDFR3xGw7IEjD"
            + "UNqruu7DlHY6jctiVJSii9UNEVetSo9AAzfROxRjROg38VsWxLyO9wEMBv/8"
            + "H8ur+zOtmQPGqirNXmN+pa08OvZin9kh7CgswW03xIbfsdGGGLRAWtvCnEwJ"
            + "mS2tEfH1SZcuVLpMomhq3FU/jsc12k+vq/jw4I2cmfDL41ieK72bwNj8xUXu"
            + "JHeoFSPGX4z+nsJUrFbFG4VBuDs2Y0SCWLyYZvdjvJwYjfqtyi/RoFSZjGHF"
            + "crstf9YNQ0vW0efCJ7pUBH44OrbnCx5ng2U5jFm1b3HBIKA2RX+Tlhv14MgT"
            + "KSftPZ67eSmgdsyPuQAdMu6fEdBMpVKMNZNRV565690sqi+1jOmH94TUX8XU"
            + "2pRQj6eGGLq6lgGnnDabcePUEPXW8zW2KYrDKYJ/1QZmVGldvlqnjZMNhIO+"
            + "Afsqax/P8RBjMduGqdilGdRzbN8PdhVaN0Ys+WzFxiS9gtaA2yPzcQuedWDN"
            + "T7sIrfIapgFYmmHRQ7ht4AKj+lmOyNadONYw+ww+8RzHB1d2Kk+iXeZCtvH0"
            + "XFWJZtuoGKSt/gkI0E2vpDfMbLaczaRC7ityO0iJs25ozP4JhZRBVvOmpxc9"
            + "YuIetbTnTf1TLJKXDgt1IwPZeugbofSeiNv117lx8VgtvMYFD4W+WQlB8HnO"
            + "C8NOYjkMPElc6PCMB9gGm0cIu1fKLvY8ycLav93JJjdDuC0kgKLb2+8mC5+2"
            + "DdMkcfgW6hy4c98xnJs8enCww3A4xkRbMU13zMq70liqmKHV2SSurg5hwUHM"
            + "ZthT8p988ZBrnqW24lXfMBqTK4YtIBMeMnvKocYBXr96ig3GfahI1Aj2Bw2e"
            + "bpZTVeayYUd+2xX8JJMdqna6Q61AL8/eUhJUETz5+fgQJtPjcKmdJfVHO6nB"
            + "vOk1t/rjK17eiXLxHCyvfP+Tw8lSFOhcvr4eIeG8WfsWNRu2eKKosOU7uash"
            + "QpnvQieqDeijuRxf+tbbJ5D86inwbJqdxra7wNuZXmiaB9gFDzNbNjhtL+6i"
            + "gUyX/iQHKi9bNK+PH6pdH/gkwnG/juhdgqoNY6GRty/LUOPgXD+r5e/ST16R"
            + "vnlwrlKp5FzRWBEkem+dhelj3rb+cxKEyvPe3TvIUFcmIlV1VCRQ1fBHtX18"
            + "eC3a3GprH8c40z3S/kdyk7GlFQ27DRLka+iDN05b+MP5jlgvfqYBKxwLfeNu"
            + "MpxWoCUvYWiQdMih86/l0H+0o5UB8SqRbpuvr6fY910JCk0hDaO1pgB3HlRz"
            + "k1vb46pg25heXQm3JmO+ghxjOGliYBWjl8p7AfRS9cjS8ca+X02Mv9Viv7Ce"
            + "3+Gz0MVwfK98viJ3CFxkaEBlM2LM0IeUQbkHG+YwYaTSfl4GYyrug4F0ZdrA"
            + "KeY9/kIxa/OJxjcIMs2H+2mSpxmrb7ylmHZ2RB8ITiduRVtO091hn/J7N+eT"
            + "h6BvLBKIFU+UFUdgjxoDNDk7ao++Mu9T3dQfceFBOYzW9vMQgX30yaPLSdan"
            + "ZMAP0VtiNjCCASsGCSqGSIb3DQEHAaCCARwEggEYMIIBFDCCARAGCyqGSIb3"
            + "DQEMCgECoIGyMIGvMFUGCSqGSIb3DQEFDTBIMCcGCSqGSIb3DQEFDDAaBAiQ"
            + "Owewo16xzQICCAAwCgYGKoUDAgIKBQAwHQYGKoUDAgIVMBMECHSCNJJcQ2VI"
            + "BgcqhQMCAh8BBFYCyRRpFtZgnsxeK7ZHT+aOyoVmzhtnLrqoBHgV4nJJW2/e"
            + "UcJjc2Rlbzfd+3L/GWcRGF8Bgn+MjiaAqE64Rzaao9t2hc3myw1WrCfPnoEx"
            + "VI7OPBM5FzFMMCMGCSqGSIb3DQEJFTEWBBTV7LvI27QWRmHD45X2WKXYs3ct"
            + "AzAlBgkqhkiG9w0BCRQxGB4WAGMAcABfAGUAeABwAG8AcgB0AGUAZDA+MC4w"
            + "CgYGKoUDAgIJBQAEIJbGZorQsNM63+xozwEI561cTFVCbyHAEEpkvF3eijT8"
            + "BAgY5sDtkrVeBQICCAA=");

    byte[] certChainCycle = Base64.decode(
        "MIIKEAIBAzCCCcoGCSqGSIb3DQEHAaCCCbsEggm3MIIJszCCAyAGCSqGSIb3"
            + "DQEHAaCCAxEEggMNMIIDCTCCAwUGCyqGSIb3DQEMCgECoIICsjCCAq4wKAYK"
            + "KoZIhvcNAQwBAzAaBBQesw38x26DXisTDrMMSoAanDOAQgICBAAEggKAja8F"
            + "U82RAAxhc36SWNXgWGV4CDSbDLFjlJuuXLTelz77KcX4dqPOQdKakm3OVl96"
            + "cbp6mWNSOoo0F8bh/Qu51vayt7hT5NIuI8jJ/Q1FYUffMKRxGt14JwuuTQ8W"
            + "5DO3z7422fm/rUu+Nkd6y+Sr0Q3FAE8QH/vNc9aUwusVAihr0AZCdT0/HwxK"
            + "AKAXLtMHeTWRpdq3WPSilPEWeeZI9Gk14uKbjEeQIUsa8IujSxTE43XwNRQN"
            + "z3Qm4oMxGOZP+DPxuKnj+Ug1OXgX5x+GD2fbwytzss9Isv/Zq8wq0gO3t1Ru"
            + "PjpxPt/MH2PxNLe4JJTxg1tIXfNP5ZU1SivcIjGLWWcEu+xADG9uq2eDBOja"
            + "mW2ZQ1cInSQw8mKcBbX7aEl0NVadSMfxMZxIw0unmoNEETmScoGr50G4Ha5H"
            + "ty1iJLNtI69MUA1c2DsoOqyzlnumTTLwuqsZ/E8rFLfO4sHncMxMRdmCEUjn"
            + "N2ZOfRqMrgtSFfBsYQ5YjxJ6CI1DLAJwIJhvx8tZgyGItgiI8pSyG8xsRliI"
            + "WPQzocO39zHK0hG6ERGnfJyll62/MlDNl9BqjobswPu97BV9nMtPIl3yVBPa"
            + "sZxj5LUPYt5nmBlIjIkT5K4cEOIWHKCHPOnAsk8AGW/vrugBcTsyw9nAsRx+"
            + "PbmOmmgyo0g2SiPsUX0fGQIWOBVZNxkGP/E4qgDOFS0YavxrdUd2Bgo9q9Sc"
            + "hENPI9wjhPztR2UNLtBviWd8utQJ7NhX+6guWEE4AN6Th/xLb/pe9c0sIsEO"
            + "41ViDbu4wDGUz6kw3fpXjIu7i6QKniWXEUL9uuchUgZD1GJHQLhD8xgdR6YQ"
            + "5SwfIadoWTFAMBkGCSqGSIb3DQEJFDEMHgoAYwB5AGMAbABlMCMGCSqGSIb3"
            + "DQEJFTEWBBRoHxEy+w9gB2sa3ykN2Ok7sb3AajCCBosGCSqGSIb3DQEHBqCC"
            + "BnwwggZ4AgEAMIIGcQYJKoZIhvcNAQcBMCgGCiqGSIb3DQEMAQYwGgQU40Mi"
            + "gMmdUNKyHyGi8miA/3bKZO0CAgQAgIIGOIk1Ouu1n1yoHWGM7YsLpB5fqK6D"
            + "LbhUoxsshDSxqemUX3QDJQVmPC9wQOUp1BUapkfB3uxsM15uUG/EUAPlF3iW"
            + "0MKDpmcKTC8y1WzMtgZBmmXwRUbguH2gmn4nd6lI2SkLWQg5boQ47aHjZLO2"
            + "MZsH1b/DUoT4m6fSrgsMnIVh03z1Gs2XO+Ky3qXqQJM9T3VtCfmeIJBIM2eP"
            + "YqvWfnvoGZZZA+pmqVUSMu6q0U7cDA5CD9zhZ87tZvaJeQ198fVIKpMUHBdf"
            + "WRGY/opZh4YTfqn+ZiiysEa9jjjx4hSkxS2XGkyUfwPEx4/1E2AdIBfi3KKW"
            + "BSyx8hurMyf89YsjxqJudfCAQI2GdWLDEXwwHMi1mM3wn5NVFzZUqM/u+t2W"
            + "f3gJGfykxwECxrn4TmerRJ3znyn7soLPEyy6Pp+JPNLyen3Z8gva5tU7Y2J4"
            + "aW6YGbBuQ9iW6QcMA93UtWBMGRAJL1jZ9WDguaTkvH8ffSj90jfu7iTHCm/P"
            + "4EEtEV7D4ciyLc5xVyq7gIQnIIViVRifAHyjbazrIFQ2yXYwINAk0yNmDqxu"
            + "8W4KNxkhNTGvQP/kkk+oDpSCa7XfxMpny+2BudjEryen2q3skMp3HjU/svHQ"
            + "+4Y9kxZ5rVYII9S8TRFmgxiRO7cQCdNEwiZndQVGahjVbLI3Jp3vmQhLg+2l"
            + "QF07yT7Q0nxeyhbpDGUEizUyIKzs9Or0DEHbq0StU3YwLgHGLlllARLm0eAO"
            + "SVhuxKGATS6GtCb/0jmzV+kX4GrK1Qkmit3Xxt9Lbq9b2v2eSMANqGrGpYyr"
            + "ETfJ5Ri/UL0nF7M9+tXrrZam1dEM5nJXR04rXQXjxxIuxsrz5xhvS/I+45RY"
            + "VKN9l1yw80wNYJlE3Un/eUxT0szk6XA7eguhB6ULGTZNDUMZdELAtwPcq+E4"
            + "4+0oih/XLzo/losH10RZ1bBf58mFVl/SlZ0CDE3x6GnFyH/tyTb6pR3Vre1v"
            + "TcBod/rkTyEnkPlFSztbBfCXXIRUcSUcbVXge3Vqn7Orhq1+sb6MPcr88uhU"
            + "c9Z6g6oKf1liIhiELpMZ5qG06hTwmMlE8prE0tdReGP/eaS2eCu8MyN70adT"
            + "IfW1PAopoZTfDYKxJYdsJUVkUojZUvmJ21sNeNREPaFBbwncHBR/y19afhqE"
            + "yyvyzDhDJ1D81TkFUR0OwGk7FvV/5JEQCyJq0wIty9G6mJRbUi2tjCc5WpP7"
            + "edDW5PBS/rfJPTDMGLy80LlD+obCTFc0sSaBI+dag02Xmxe31V9c96VPOsFt"
            + "GQ532OFwZU52E9zYLQSL8L2sdNlEK+OCvTd1MNVbH6PGBYgxrmoDfNBQlYBh"
            + "yX2R9wFClraNUBBV9Dtebb6MSqPW7m8xZWAXCmXkDqR9A9kP6qTMd4X3gSFT"
            + "qJaezTWbHH44PTgffpK5A1ZBQj37se82QWtBKNPU14KEVvXcI+uuM/TmoAJY"
            + "0hqMeXK/1JfzhxTuJsJl+c45LuGjq9dLY9tgTSqMLeKOqal7sLH1AVs4BCCA"
            + "J/sHN5pgOjQNLZ1Zup5mZHXR/ynIhKnpYDADOfnAXLizn/UZZFs5huYJYQEQ"
            + "K7zcDuzPuxcmFVqUa4AyL9Ul1N42rBx3VsKZ+pvcBTQU5mWsaYwPFox4wLx0"
            + "HITx7v7cFYsqki7IHfgnvpJlIS8hrvqqXHl75b61T7ZfJMJNQjhf29//OZ36"
            + "QU4mj7lXwudAe+qAJbn1De5B54dQhtLA7B6sX7/7Sy6xP42QJqXhlWngbhF1"
            + "IsrgZZrFPJ7zeaKnjOfrLWr8bs1nthHNNoL4cqlPuYtliUGy5zxj9bpQH8xj"
            + "oh8+PjTOT4H57IvUN/US/6R0awy8WafJ211diVjbU2IbjS/P+xa6Xlbaql4Z"
            + "KlvXRmoMZNl6xPbJg4x6t2anadNmuS7TXHqfTpp+UxeSsr1phyPmxQZPujZY"
            + "BADnjfNhTRi7esePheR/DPaPLwjllhetm+U7s7EZzMCdEcd5RB/jiceqRQ5b"
            + "xoqSyvIW1ZcdTzRQEAFAhnMWRdVT0O0KYDATiSVqcBr0b70dIQ0lZvYk/TUy"
            + "FdYhRXqC8Gzh8xQZPr3CBGoB02pWpp0Hbb5bHtpf3VnfsEmfwBtRPaEUMD0w"
            + "ITAJBgUrDgMCGgUABBSsUQPThQeWi8r3oQZ22tcQW2dDqgQUSOpRzALP2lIV"
            + "GOtPKKbIhe5YCbkCAgQA");

    byte[] gostOpenSSLIntegerDPfx = Base64.decode(
        "MIIC/wIBAzCCAsUGCSqGSIb3DQEHAaCCArYEggKyMIICrjCCAc8GCSqGSIb3"
            + "DQEHBqCCAcAwggG8AgEAMIIBtQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw"
            + "DgQIb1OLAOp7o6ACAggAgIIBiFSfDqzkF2Lv9arM6fdxKrixa9Zu8sGkrsbN"
            + "1mYEPYRRJFyfTHB2cOn4yl2I6Ldo9m9GKtnTGGYugMTAFLdBNe0f7X0c4fjr"
            + "norM2ODUDfzuqI0a54DLwixvV4U9Q0qakLKQJDAHnCSsWu7N8tRktpYt9oIZ"
            + "3sVJ9r01+yxBrDOapAqT3UtaFILSiUU94Zdyehu9hmL3cq33s7Y+orfESC8A"
            + "O7OYYks7c6sEjNsvUHag2bC3GClzEapiboIs2F2vb12NoiQ0skU3dbO7Jr1T"
            + "P6qkjBYFvG31c3vG8pNxJ7iwJr5+FonJ6uVg3y8EmYCROD5Eyd0MeGaa+eBr"
            + "z/CPFaaM50NT6RAL3CTmfqOEzOlXE2qyKZiPD65TxowbjYOmDh8Tb/mfOQUK"
            + "hx8Tgzttk0CHHHZmUQkMm0RXDj/n07JaeGuQJQ1pK/3Wg7ejfGxj7eFgzmPU"
            + "jOhIAAe/fwOkxUC8quv/+db/L+EeSQBSEyacU5MliXwOPVytMUOP4pFMtonw"
            + "C6NzBU5JMIHYBgkqhkiG9w0BBwGggcoEgccwgcQwgcEGCyqGSIb3DQEMCgEC"
            + "oHIwcDAcBgoqhkiG9w0BDAEDMA4ECF6BMzmkD7DbAgIIAARQlev2YN09882U"
            + "niwvu9nMIgS3hmjSlqlpkf5aYQLosSy5eaOWCq0Vskqgv5i+77vKyQYcKOH0"
            + "VnQYu98kWUgZy4fNfesufL+m3d29LX/JGdoxPjAXBgkqhkiG9w0BCRQxCh4I"
            + "AHQAZQBzAHQwIwYJKoZIhvcNAQkVMRYEFIaC9GvZM/XUGW4U50bkjCfsTrW8"
            + "MDEwITAJBgUrDgMCGgUABBT3iAwuHw7KQXrl09gBkHaUVbOoBAQIIm90qua1"
            + "2i4CAggA");

    private static byte[] certsOnly = Base64.decode(
        "MIICnwIBAzCCApgGCSqGSIb3DQEHAaCCAokEggKFMIICgTCCAn0GCSqGSIb3" +
            "DQEHAaCCAm4EggJqMIICZjCCAmIGCyqGSIb3DQEMCgEDoIICHDCCAhgGCiq" +
            "GSIb3DQEJFgGgggIIBIICBDCCAgAwggFpoAMCAQICBHcheqIwDQYJKoZIhv" +
            "cNAQELBQAwMjENMAsGA1UEChMERGVtbzENMAsGA1UECxMERGVtbzESMBAGA" +
            "1UEAxMJRGVtbyBjZXJ0MCAXDTE5MDgzMTEzMDgzNloYDzIxMDkwNTE5MTMw" +
            "ODM2WjAyMQ0wCwYDVQQKEwREZW1vMQ0wCwYDVQQLEwREZW1vMRIwEAYDVQQ" +
            "DEwlEZW1vIGNlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKOVC4" +
            "Qeg0KPAPRB9WcZdvXitiJ+E6rd3czQGNzEFC6FesAllH3PHSWuUZ2YjhiVM" +
            "YJyzwVP1II04iCRaIc65R45oVrHZ2ybWAOda2hBtySjQ2pIQQpoKE7nvL3j" +
            "JcHoCIBJVf3c3xpfh7RucCOGiZDjU9CYPG8yznsazb5+fPF/AgMBAAGjITA" +
            "fMB0GA1UdDgQWBBR/7wUDwa7T0vNzNgjOKdjz2Up9RzANBgkqhkiG9w0BAQ" +
            "sFAAOBgQADzPFsaLhVYD/k9qMueYKi8Ftwijr37niF98cgAHEtq6TGsh3Se" +
            "8gEK3dNJL18vm7NXgGsl8jUWsE9hCF9ar+/cDZ+KrZlZ5PLfifXJJKFqVAh" +
            "sOORef0NRIVcTCoyQTW4pNpNZP9Ul5LJ3iIDjafgJMyEkRbavqdyfSqVTvY" +
            "NpjEzMBkGCSqGSIb3DQEJFDEMHgoAYQBsAGkAYQBzMBYGDGCGSAGG+Watyn" +
            "sBATEGBgRVHSUA");

    static byte[] JKS_Store = Base64.decode(
        "/u3+7QAAAAIAAAAUAAAAAgAGY2VydDE5AAABVrqTp2QABVguNTA5AAACETCC"
            + "Ag0wggG3oAMCAQICARQwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAkFV"
            + "MSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
            + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZI"
            + "hvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0x"
            + "NjA4MjQwMzIzMjRaFw0xNjA4MjQwMzI1MDRaMIGPMQswCQYDVQQGEwJBVTEo"
            + "MCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAG"
            + "A1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3"
            + "DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwWjANBgkq"
            + "hkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9"
            + "umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkq"
            + "hkiG9w0BAQsFAANBAAoDCxo2es5N6DeKPLEUAJMHGqFCc+FC5hp43qs5IwmR"
            + "eWW1uUTTJg+eRL9DkJqc1Q5jjsSnE0OerHLr5QlvwxEAAAACAAZjZXJ0MTgA"
            + "AAFWupOnYgAFWC41MDkAAAIRMIICDTCCAbegAwIBAgIBEzANBgkqhkiG9w0B"
            + "AQsFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2Yg"
            + "dGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UE"
            + "CAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bi"
            + "b3VuY3ljYXN0bGUub3JnMB4XDTE2MDgyNDAzMjMyNFoXDTE2MDgyNDAzMjUw"
            + "NFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRo"
            + "ZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgM"
            + "CFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91"
            + "bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdP"
            + "FqlwgrIr5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWg"
            + "QMYGiHQg4z2R7X7XAgERMA0GCSqGSIb3DQEBCwUAA0EAglkbmZACXbtqdfpA"
            + "PJKpEhJqG8WVSqxUMHqZCrMYBAxKCnfBTGKNoV506WY/KhhJICK8xg17iL+1"
            + "NhCrt0zq8QAAAAIABmNlcnQxNwAAAVa6k6dhAAVYLjUwOQAAAhEwggINMIIB"
            + "t6ADAgECAgESMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJBVTEoMCYG"
            + "A1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UE"
            + "BwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJ"
            + "ARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwHhcNMTYwODI0"
            + "MDMyMzI0WhcNMTYwODI0MDMyNTA0WjCBjzELMAkGA1UEBhMCQVUxKDAmBgNV"
            + "BAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcM"
            + "CU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEW"
            + "IGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMFowDQYJKoZIhvcN"
            + "AQEBBQADSQAwRgJBALSn5GFwV08WqXCCsivli2oqYpeYQZvhKHKkvbpibPrp"
            + "kA92q/sSE53OXeVlZPqytlQxZaBAxgaIdCDjPZHtftcCAREwDQYJKoZIhvcN"
            + "AQELBQADQQCoKlzmG19aQKP9iqQT3k6sMzZdVZkRuHwaPTvdTVaSZtIsl2YX"
            + "FzIygviAHkVWkoF7iuY3T1skQD+Cjpj4ri6rAAAAAgAGY2VydDE2AAABVrqT"
            + "p18ABVguNTA5AAACETCCAg0wggG3oAMCAQICAREwDQYJKoZIhvcNAQELBQAw"
            + "gY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBC"
            + "b3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZp"
            + "Y3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5"
            + "Y2FzdGxlLm9yZzAeFw0xNjA4MjQwMzIzMjRaFw0xNjA4MjQwMzI1MDRaMIGP"
            + "MQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91"
            + "bmN5IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0"
            + "b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNh"
            + "c3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKy"
            + "K+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0"
            + "IOM9ke1+1wIBETANBgkqhkiG9w0BAQsFAANBAA/zyjwMVvjZt5aCStPAShfH"
            + "BK2UDhEnu308Ir7k0M0g46CGD2lmaIn8wY1pBm+eZj5mKCK1iD6L7THJIxlh"
            + "NUkAAAACAAZjZXJ0MTUAAAFWupOnXQAFWC41MDkAAAIRMIICDTCCAbegAwIB"
            + "AgIBEDANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoM"
            + "H1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1l"
            + "bGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZl"
            + "ZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTE2MDgyNDAzMjMy"
            + "NFoXDTE2MDgyNDAzMjUwNFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9U"
            + "aGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxi"
            + "b3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVk"
            + "YmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUA"
            + "A0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7"
            + "EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERMA0GCSqGSIb3DQEBCwUA"
            + "A0EArVzFb0Nh8n2Rm1I4Mrxk6vTPbbfPy7akWKp5F1AKa4rwwz37Ki+i3/qQ"
            + "5/j1UsuG0v9dCXkZbGMSzW5uqu57QgAAAAIABmNlcnQxNAAAAVa6k6dcAAVY"
            + "LjUwOQAAAhEwggINMIIBt6ADAgECAgEPMA0GCSqGSIb3DQEBCwUAMIGPMQsw"
            + "CQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5"
            + "IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3Jp"
            + "YTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3Rs"
            + "ZS5vcmcwHhcNMTYwODI0MDMyMzI0WhcNMTYwODI0MDMyNTA0WjCBjzELMAkG"
            + "A1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBD"
            + "YXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWEx"
            + "LzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUu"
            + "b3JnMFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALSn5GFwV08WqXCCsivli2oq"
            + "YpeYQZvhKHKkvbpibPrpkA92q/sSE53OXeVlZPqytlQxZaBAxgaIdCDjPZHt"
            + "ftcCAREwDQYJKoZIhvcNAQELBQADQQBk9jFHwJ9RMpS3cTfFD4Jn94ZJo0Oo"
            + "4pjPdpt2/uIqSOEA5QHgJVkY4+23hbgUvDDk6cU95tAINYMj1N7QlirNAAAA"
            + "AgAGY2VydDEzAAABVrqTp1oABVguNTA5AAACETCCAg0wggG3oAMCAQICAQ4w"
            + "DQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUg"
            + "TGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3Vy"
            + "bmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFj"
            + "ay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0xNjA4MjQwMzIzMjRaFw0x"
            + "NjA4MjQwMzI1MDRaMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExl"
            + "Z2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5l"
            + "MREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2st"
            + "Y3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBG"
            + "AkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d"
            + "5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQsFAANBAF6x"
            + "Fni4cQsdBiE+ksluexlGSGV721kieRIGrgQP9JWbyvDw3H8/AKrcjSEOru0M"
            + "U3utomkk4ympScU+eL45bQUAAAACAAZjZXJ0MTIAAAFWupOnWAAFWC41MDkA"
            + "AAIRMIICDTCCAbegAwIBAgIBDTANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UE"
            + "BhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0"
            + "bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAt"
            + "BgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3Jn"
            + "MB4XDTE2MDgyNDAzMjMyNFoXDTE2MDgyNDAzMjUwNFowgY8xCzAJBgNVBAYT"
            + "AkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxl"
            + "MRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJ"
            + "KoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzBa"
            + "MA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb"
            + "4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgER"
            + "MA0GCSqGSIb3DQEBCwUAA0EAcNDNuol1VdqEOBvZCJLWkNFVUfyIMX7Y4Czk"
            + "hOJ9PWH97EOr989fdiBBDTKS5pQlI32z932cwH9vYZZ0TNWAngAAAAIABmNl"
            + "cnQxMQAAAVa6k6dXAAVYLjUwOQAAAhEwggINMIIBt6ADAgECAgEMMA0GCSqG"
            + "SIb3DQEBCwUAMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lv"
            + "biBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREw"
            + "DwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5"
            + "cHRvQGJvdW5jeWNhc3RsZS5vcmcwHhcNMTYwODI0MDMyMzI0WhcNMTYwODI0"
            + "MDMyNTA0WjCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24g"
            + "b2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8G"
            + "A1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0"
            + "b0Bib3VuY3ljYXN0bGUub3JnMFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALSn"
            + "5GFwV08WqXCCsivli2oqYpeYQZvhKHKkvbpibPrpkA92q/sSE53OXeVlZPqy"
            + "tlQxZaBAxgaIdCDjPZHtftcCAREwDQYJKoZIhvcNAQELBQADQQAtpD6dgY7n"
            + "+wnuKxNsXfMr21VSx5PLqqbxVUMHl/NzonLFSYx0oMPJVWwGYz0uNlglwTCx"
            + "l2cTpc3kQTSvUSGzAAAAAgAGY2VydDEwAAABVrqTp1UABVguNTA5AAACETCC"
            + "Ag0wggG3oAMCAQICAQswDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAkFV"
            + "MSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
            + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZI"
            + "hvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0x"
            + "NjA4MjQwMzIzMjRaFw0xNjA4MjQwMzI1MDRaMIGPMQswCQYDVQQGEwJBVTEo"
            + "MCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAG"
            + "A1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3"
            + "DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwWjANBgkq"
            + "hkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9"
            + "umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkq"
            + "hkiG9w0BAQsFAANBALLlTLPkOYTYbI0CtvvJpThX4LvAspq5PH3LacfWB+tj"
            + "/gEQhWrODkFSS2dWwNdR6IQpWl0L2xZHJCYG93IdJC0AAAACAAVjZXJ0OQAA"
            + "AVa6k6dUAAVYLjUwOQAAAhEwggINMIIBt6ADAgECAgEKMA0GCSqGSIb3DQEB"
            + "CwUAMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0"
            + "aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREwDwYDVQQI"
            + "DAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJv"
            + "dW5jeWNhc3RsZS5vcmcwHhcNMTYwODI0MDMyMzI0WhcNMTYwODI0MDMyNTA0"
            + "WjCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhl"
            + "IEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwI"
            + "VmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3Vu"
            + "Y3ljYXN0bGUub3JnMFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALSn5GFwV08W"
            + "qXCCsivli2oqYpeYQZvhKHKkvbpibPrpkA92q/sSE53OXeVlZPqytlQxZaBA"
            + "xgaIdCDjPZHtftcCAREwDQYJKoZIhvcNAQELBQADQQB+rfnwKrVxuYjygj9Y"
            + "VF2r7MWJj6YyaRmcZHQrKw7zmXMAnpXaJHaRvZ5yEZtWo57p+fDQLk5u0QoO"
            + "MrSX8B8PAAAAAgAFY2VydDgAAAFWupOnUgAFWC41MDkAAAIRMIICDTCCAbeg"
            + "AwIBAgIBCTANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNV"
            + "BAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcM"
            + "CU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEW"
            + "IGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTE2MDgyNDAz"
            + "MjMyNFoXDTE2MDgyNDAzMjUwNFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQK"
            + "DB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlN"
            + "ZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBm"
            + "ZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEB"
            + "AQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4ShypL26Ymz66ZAP"
            + "dqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERMA0GCSqGSIb3DQEB"
            + "CwUAA0EAK/s6ltnp3JLH93++PIJ0Ui68ZcQP8CFcOfy/7tbeIameAdPb74pI"
            + "QVLsJOQl57/ybe6jEjDNG+Ahd9Ce57GUQQAAAAIABWNlcnQ3AAABVrqTp1AA"
            + "BVguNTA5AAACETCCAg0wggG3oAMCAQICAQgwDQYJKoZIhvcNAQELBQAwgY8x"
            + "CzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3Vu"
            + "Y3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3Rv"
            + "cmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2Fz"
            + "dGxlLm9yZzAeFw0xNjA4MjQwMzIzMjRaFw0xNjA4MjQwMzI1MDRaMIGPMQsw"
            + "CQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5"
            + "IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3Jp"
            + "YTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3Rs"
            + "ZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WL"
            + "aipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9"
            + "ke1+1wIBETANBgkqhkiG9w0BAQsFAANBAJDkyw3j/GCV2/2aLmYHF2WxBADi"
            + "tlWWLu0X9Aer0LYUskv52EK2edFHq0tVYlRKDpJcPtfmQSCu5cciJ51aqy8A"
            + "AAACAAVjZXJ0NgAAAVa6k6dOAAVYLjUwOQAAAhEwggINMIIBt6ADAgECAgEH"
            + "MA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhl"
            + "IExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBwwJTWVsYm91"
            + "cm5lMREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJh"
            + "Y2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwHhcNMTYwODI0MDMyMzI0WhcN"
            + "MTYwODI0MDMyNTA0WjCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBM"
            + "ZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJu"
            + "ZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNr"
            + "LWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMFowDQYJKoZIhvcNAQEBBQADSQAw"
            + "RgJBALSn5GFwV08WqXCCsivli2oqYpeYQZvhKHKkvbpibPrpkA92q/sSE53O"
            + "XeVlZPqytlQxZaBAxgaIdCDjPZHtftcCAREwDQYJKoZIhvcNAQELBQADQQCY"
            + "XkifQxQldNLcX6U1W7jFizMLbcr5gKw2m9Y4AknIwJ5L5l89wXOc0xfldWWF"
            + "ohBCKbHMIwpQZykmm1DWi0h4AAAAAgAFY2VydDUAAAFWupOnTAAFWC41MDkA"
            + "AAIRMIICDTCCAbegAwIBAgIBBjANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UE"
            + "BhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0"
            + "bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAt"
            + "BgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3Jn"
            + "MB4XDTE2MDgyNDAzMjMyNFoXDTE2MDgyNDAzMjUwNFowgY8xCzAJBgNVBAYT"
            + "AkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxl"
            + "MRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJ"
            + "KoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzBa"
            + "MA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb"
            + "4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgER"
            + "MA0GCSqGSIb3DQEBCwUAA0EAogFA+GTVCquJxRCXggv9TcvtT3jXEQ2n+ftY"
            + "IcL4R05pqg/3kGyJpj73BI09PykEWx1nwT+mcZYZg6W/AQgomwAAAAIABWNl"
            + "cnQ0AAABVrqTp0oABVguNTA5AAACETCCAg0wggG3oAMCAQICAQUwDQYJKoZI"
            + "hvcNAQELBQAwgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9u"
            + "IG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAP"
            + "BgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlw"
            + "dG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0xNjA4MjQwMzIzMjRaFw0xNjA4MjQw"
            + "MzI1MDRaMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBv"
            + "ZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREwDwYD"
            + "VQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRv"
            + "QGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfk"
            + "YXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2"
            + "VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQsFAANBAC7YKkm1uS5C"
            + "XVTXObt9oYXXrtN3+Wvbtl+9HNgX3CVzFGDo70GSuCpgIq2lxMZHf8YrRKTv"
            + "t+o6Dasw69ubfg8AAAACAAVjZXJ0MwAAAVa6k6dIAAVYLjUwOQAAAhEwggIN"
            + "MIIBt6ADAgECAgEEMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYDVQQGEwJBVTEo"
            + "MCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAG"
            + "A1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3"
            + "DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwHhcNMTYw"
            + "ODI0MDMyMzI0WhcNMTYwODI0MDMyNTA0WjCBjzELMAkGA1UEBhMCQVUxKDAm"
            + "BgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNV"
            + "BAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0B"
            + "CQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMFowDQYJKoZI"
            + "hvcNAQEBBQADSQAwRgJBALSn5GFwV08WqXCCsivli2oqYpeYQZvhKHKkvbpi"
            + "bPrpkA92q/sSE53OXeVlZPqytlQxZaBAxgaIdCDjPZHtftcCAREwDQYJKoZI"
            + "hvcNAQELBQADQQClzdQAN4gHAMyvFabp019/e73AsNbL+zNzvPGZdXjYZIve"
            + "y9RjQV2Vtlx3kN7wJX9bqBJQLyHKdUpXSFTvHh1dAAAAAgAFY2VydDIAAAFW"
            + "upOnRgAFWC41MDkAAAIRMIICDTCCAbegAwIBAgIBAzANBgkqhkiG9w0BAQsF"
            + "ADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhl"
            + "IEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwI"
            + "VmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3Vu"
            + "Y3ljYXN0bGUub3JnMB4XDTE2MDgyNDAzMjMyNFoXDTE2MDgyNDAzMjUwNFow"
            + "gY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBC"
            + "b3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZp"
            + "Y3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5"
            + "Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlw"
            + "grIr5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYG"
            + "iHQg4z2R7X7XAgERMA0GCSqGSIb3DQEBCwUAA0EAVlnwlvG4I9JVLkMoN5MJ"
            + "4vIw4qXSLxdey++wMdF4aSoOe2I3p4o97VhNZBPYZbZCUw2ShsyhkXOytgXd"
            + "NYdCBgAAAAIABWNlcnQxAAABVrqTp0QABVguNTA5AAACETCCAg0wggG3oAMC"
            + "AQICAQIwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQK"
            + "DB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlN"
            + "ZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBm"
            + "ZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzAeFw0xNjA4MjQwMzIz"
            + "MjRaFw0xNjA4MjQwMzI1MDRaMIGPMQswCQYDVQQGEwJBVTEoMCYGA1UECgwf"
            + "VGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTESMBAGA1UEBwwJTWVs"
            + "Ym91cm5lMREwDwYDVQQIDAhWaWN0b3JpYTEvMC0GCSqGSIb3DQEJARYgZmVl"
            + "ZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEF"
            + "AANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar"
            + "+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQsF"
            + "AANBAKqAyBtKhOgy4NmjV2fc1JlcM2sQ8rEfZ9+PqJixFAqvKSLl6gASZ0dW"
            + "Mrmof6ZkKSjEerwoPOXdKJ1VeqOjMBQAAAACAAVjZXJ0MAAAAVa6k6dCAAVY"
            + "LjUwOQAAAhEwggINMIIBt6ADAgECAgEBMA0GCSqGSIb3DQEBCwUAMIGPMQsw"
            + "CQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5"
            + "IENhc3RsZTESMBAGA1UEBwwJTWVsYm91cm5lMREwDwYDVQQIDAhWaWN0b3Jp"
            + "YTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3Rs"
            + "ZS5vcmcwHhcNMTYwODI0MDMyMzI0WhcNMTYwODI0MDMyNTA0WjCBjzELMAkG"
            + "A1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBD"
            + "YXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWEx"
            + "LzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUu"
            + "b3JnMFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALSn5GFwV08WqXCCsivli2oq"
            + "YpeYQZvhKHKkvbpibPrpkA92q/sSE53OXeVlZPqytlQxZaBAxgaIdCDjPZHt"
            + "ftcCAREwDQYJKoZIhvcNAQELBQADQQAlNXGzWfJmbvK4blA3GCHRO4BMc9of"
            + "9LOKSnZdIHpdxkLqoxqWhAbph3zqhDYOe6SuRR1ZZoOnbKVICqm9W1ps967o"
            + "ndfs5jZEtLNpj106EQT4x9U=");
    static final char[] JKS_TEST_PWD = "jkstest".toCharArray();

    private static final byte[] repeatedLocalKeyIdPfx = Base64.decode(
        "MIISUQIBAzCCEhcGCSqGSIb3DQEHAaCCEggEghIEMIISADCCCDcGCSqGSIb3"
            + "DQEHBqCCCCgwgggkAgEAMIIIHQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw"
            + "DgQICxSuOGaRUU4CAggAgIIH8EeSXfPe3pE5Dzzhpdd1OyFTfQnAMDBkTpxh"
            + "TYnvxZc9uKGmMils1HHS6iKV+VfIyUUvnFoNULy9DIQkkOZK8panWq8ORX+8"
            + "VgdJrlxbUGOB/O4MXgAptWpMHsL4Dc4CvIH3iR5oaRLI53e/9X8Y48T/k8Xx"
            + "lKTS08lM6AP6rHjCEgKtkj4xVU1m+GZibc52edUtW5Tc3731n4n9kf85XGrx"
            + "UJ4+PmwHx0DGjpmBRlAk0/AnQrW4MYIx5tuhR3412M2WaJM2M8pizCcMWVyn"
            + "YlBJ8PkgfS3t5Nq2KJNWAnZj54zfINDKaLNL0SnZakN0+DHiMOB+Y7kFIqKD"
            + "CM6aUP5LBpWYsZKUkTX6gcOOhz0+nzrtmP4tGL3xGpazrrOoZTrzQDZBVv1y"
            + "KOwPoOrv0u44aVoqIXzlAm7VEHSsVkLLQouqsmqWagWypAn2zahVMR5rGflG"
            + "04IgLGBWIU4hPx59TnxyOUtYn2mGS0pK7Xyim7nHVtCC63OFqy/Pm+4TQkLc"
            + "+ZMLs8EdMtXuJSfOE5mMnPPkgwFAjF3MsG8ytjBS1xAdPCqsD4fH6MKeT/fF"
            + "A6SFYd8M0btGa30dBRAVF2DNkF0zUwtTYysh6Z25dgxAf6HKYy+SpqMOJJl9"
            + "eAGULAjFkB5i/PVDPjk7QuipgfVc35/zde38WAKXkfQuhvn9xkjtplRnhkMV"
            + "7Sgvo5Yaaz1Ee8i3VeeR79JXd9UjOSEt62AOb6Isf8hx9v87hcGD4bUQUQNl"
            + "zEHcifkEjRecB6EZHKq8MCAkz53bN2Vr6y3ET2ImBdzaYrKLixsTJNELCzbl"
            + "L+U8JXJr2RcEUOSPW8mmypvpVV5GPmSi72Qx20raTyLhrVLY4yGt+pdNGqSd"
            + "LjegYgSKnYgePXLU8pZVPSCLuZ9Bonv1l2PFPr7dQvrDALk9Q9FYLnAFc7Jf"
            + "zYIiaSNAeiFCGvMpjiNIUMS1bqeAv6bnJg7YqFS24M4gztSxxooTY1L3ILLX"
            + "aJfkYxPbQAonKgKuOHxUM6RHyxPTLLQCmLa2JeyKDEpC0pC+VL6d6UJyOI0e"
            + "o2Lu+Anby5o/fvRtww4pz2yIbMsaEzxMyu+HtWkANo+g3NSxu6VylcrUq/QQ"
            + "r5csLC+37eJyi2OKDKMSUPt3vkVk+5yu830oNHCEhn4kHCISC7rDb0QMfb8F"
            + "hvmZXILcbmdxsKc+4Lzk4rhrsn2xBu4OL2JKNBYlfIV4n5GfPBBBuMzAC6eX"
            + "2OLpaxq/DlbkKzaJtKyj6+npe8CGO/82Yl1OaG6vbLXoSD6DGMR6AHq287tq"
            + "aCSiu5J/a33BUo1DfuEFOscXHipLPvkM5JFx7L/0OfvJcioe1VOtrL9sRZ1F"
            + "8eWSonj2EEidxy6mDhbFDPMqnPo0ETay+VXNVznzmrW7mtuQ0ZOAZ84DMDUy"
            + "JallUgpK1zvwae0sIXdblTN98DGU2hFpXMu9n030BmhkEEJRbKikxpEfWcxI"
            + "0j7+276v6Z32C4BpoeGFxpfrpozwJzTBoGlkN408thpB/llqkBSeLtxEnSKO"
            + "SbpKquR6kg4FYQwq7pbKQuSjvKztIhdCDanmi+cPNppHyGmbf4yDMtWOLGhU"
            + "cLUbdMJ8jWcvDZiKwzB4s1Qka1Z8qVi5VVEPhpzh4E89WqSoRtgLbhkoy8mf"
            + "BlptXBWggXs+eR/s2YXb3nF2ZPnYQcn1+alCMM8aXf9HEeaFGEsEAsANglu9"
            + "lnlaGFLbzIeGwkpGFLVlj9Fd+s+a6OVmeaPCa1cZaTKzdC6FqHd3bxalLBc8"
            + "fDcbJPDYsTYFEajw648HG3x3oyk+P5WOa9ULup6emu/zOhH5VPJcj9CniLqq"
            + "EZDaIDPRqu0g5MZir0EdXL6FvRU2o7W8JE7fzSYxlAWcUbuY6TdaGO7SOvxq"
            + "oRKpsIzcmBLpw1t5djii/SohQR/2mJhvqETWvOerfEQr3vXnwurVUC1u/vEO"
            + "lCqCRNLH0qzQUFrwzm/kMWsaDMb85XYQpZ+StT6n5AHWNWuQG3bmZIjAY9R9"
            + "AbPWi/eSYQF/1E4qZ6WE+S2VOg3i/iVT0MtJzuGXRl1rycZv2vPiskEvVGhT"
            + "DbqPWapGugbXLIne6b0C83EtK9H8s/TdDcRupjzW9J/8+p8+DJROgg6y2wIm"
            + "SiUKHMZsuU9+e5+z87HVB9t2y0RsARJdbB9NhuTZk7ELztNponTMdJmUyIT0"
            + "phdz3U9MFEWnHccMMGo3KqopOsrGT9YqdcBSSfSOyckVBQzgzVt8ypWqusW5"
            + "j53OudlwcoudmOTdUfYoEuDWGYgoGqSEOnaU8dqkl4ZffYUIeJuTwclJd9N+"
            + "onB82b5FpzXo+sO6DWpNJ8lGE2mOqt4H/HvRwTJ5pfXlZSmGom4eq+WU6XfB"
            + "CRE6ehopnU91wey0/lceYPshOQriqoVE577xJKU3zWuWzFwBvanrN2YxptdV"
            + "xNiKabM3UmSxgGtxITEb1pCAGBTZzBL175CvmBF6VyamVe4YH7wuQ+C2jEle"
            + "xH6xo+1eWyPT5L5CSVFgiJpxX2WoI/8qvnSdagJW0+IQWk1nfNJb2aNbBu4z"
            + "Iw6txeGxtQHPhF5eyVgRDE6OannycbSOJMi14q8n4zhyJebsY1wldB31XOFV"
            + "pnCRNUcMcueAMioxliO7K81O8SiQVbIyVsc2GYQqhevdDHwj2azat60kNytq"
            + "nimsplgyD84oeMMwaqbciAOItPbdqbz7zGIwggnBBgkqhkiG9w0BBwGgggmy"
            + "BIIJrjCCCaowggmmBgsqhkiG9w0BDAoBAqCCCW4wgglqMBwGCiqGSIb3DQEM"
            + "AQMwDgQIGF7xpMpvXmgCAggABIIJSD9TY2dCx+BYL555TLN51ksuTf1NkXjD"
            + "Az1uymDqjoQ1R67CbcHU2qPKwIW3fZT7OmpiPI8cgogKBvcFnngmfeuvZYST"
            + "gOW2iD83m5PlaoIa2iXjqdPdCQF9rVwkBg6VUYWlVd9qR0LPKT3u3UsScN2d"
            + "qPeeSVRL8W4ESR6OMgiEIts50cjUwb2acqy3So9LZU77/D6uynj5+iFwYxlb"
            + "yX/70oegWqMZyiZfvGT1UNMQxF/hs0E7ZGW1RnWjixVI+p3Pvqw36mH9j3Xn"
            + "ms5Eg4mhbyBXRPIsq3/95O5NRh84R9atvR+zn1Pd59DKIUVf11w6HZoNOtH+"
            + "XrVG7MpLVFIbgxZWzr6JIOK7/bMkJi+aBwSfm3yR6U46XDYlDHfSeeL/xJFm"
            + "0QSNf6S/K7lj+AwAoOrruaxXwHxO1zlaXGo8R8P5JVgr7/mbsMF2RnXp3JrW"
            + "KIC5LsePgyy6bYBdFwbJZ/FQVFp0zCnByUvPP8xS9+TdZKvp9u6rgIzNCPFK"
            + "m1f9XkgJhIn4TEgRVp/OGYbUX2g4Gbm15TUUwyXUFsas224Cyv2RwrzpKNXv"
            + "SpriMdXtbEIzt6IRKH6oB1x5QbPz7cJhKL8pbhOUnjSourJC5S8LgazqyKaS"
            + "VIon108lGcq6xJJKySxsA74luILEpQyTgZfpSUblCeRcOMdXW0OA+K6PhXqa"
            + "e1EzWHo6F7iMTi0SSZ/XOV6Px9xV3e2vRXSt13+pzTpRZKpzVHjpkiWz7xYt"
            + "NI2Vq+4LB/ZCi3jhJLYoRYSP9XEf2ilfplK4rGD8tIEDTkFLnKv8oKA+dnwX"
            + "VNxKoJQnPuYLTDCU/KfODU4gAyefuTCH/8iAry/6UhOM9Pr50boQJ9KK5Ckz"
            + "lkptnLqP6vCSFexkETdh+Vx2Jf87EmytpUhJXS1i2EOjihWH0hEUknEip7km"
            + "a1m489qAMUzOMZ2RaIu0p/gDGlLkLem2yv6AOFcqBpQWo0yc4HaPf1Op06/7"
            + "ZkykXPyekYI0kKKMrILrW7XifSyvAaPiuXIRzH7GpRIoPmNEEnm3jSpPfkZo"
            + "ttCWxzktVVFD2ACTQXV6uDH6eiOrZpMtrg6tOqfbgdGkohfjLtnSjjfhAgTg"
            + "N+Tb7w9FgGMZjvrA9Ht50m1iqGg25la5jBfCaD1ZOoAWe1mhRiWVFuEuVewb"
            + "dA1hny6OSXxc+5v6pyXKYodMDjYW8m3hhgQfxo1vAoOIy9UWiZ+kVQbw68MO"
            + "G7mOYw4WKKDPw4LaiPVSexmu08mYJXiOU+mNlvv0GseQ6gK+sDsQKiPa8KGi"
            + "JllcaKnJ9qmO0ff5IZ2bDyAESkUgwb9CaT7yjTz+z78Q/IcAVafYLkbJb4FZ"
            + "UFUTsLfw172NW1MzTeyfHe9YtZsOUuViuFLrKoWO8fDRYcA65J30C1S8P3bU"
            + "aauukUZBoFndn6sz0DH6z+YLOjvoAlyze+692saz6OPf8iYPacq25i44He2v"
            + "sRpbqrWw3Xn1fcd2WQABQ4Ig4sntuuvG6ZYFl9//8ZtNfe6hS9iZzyP4CPiz"
            + "Q9cD15Xln24gW2EZuJ6yfgiK8AYfZIUmGu0fUO4x5kPNbkIEdb+a2HYDb4rs"
            + "m8dFVKCKDPOjEojkfFz3DXycQn79xOxs7HEg7GZtV6/jnu0tel2qHQNBPM2i"
            + "1RWHfiC+/kKWmiQlwbSYzyFcbwcPYMzGVcbJoL/SidqxcD4PeD7PnPmAHzy9"
            + "2rvGPu6m0/7HhjsMicG/fyfczY+SPSkxoxa2N46yS397tKbUVJ9SfUATJ0vM"
            + "YqnqqgKQTd0MzdQNcNOE6EozK3kCTV+6xjs1aSvwB51gp03vcw+Ln0mW4Dfd"
            + "mM+HwFre9w37DJBajEXbzkI6aHApCQdN6VexsaSyxFewwavTqwmVeSTIflpa"
            + "s2lFbJmLbMDcdgiIHyvOygg0oXy1JuFScuBZ4T21kcTAEX/hFPfLTGTUXeBA"
            + "hMY+gkdol/IB9gNPL23KLskXv4+Z9sCVheG3eAi4qeLgkqr86L8aIYa0Akdl"
            + "UnxREE0/sDeiqaV+fg/cHGa51YRVHhyG4/+//PQ46xW5ORhGnOSs7UHZB1XK"
            + "5ROgOFDe1HpKhQwWbFEaMY+CLSBFDNmMZiaoArf1r5qIqwG6fy++T0f7plDm"
            + "CdoZcV5IyIwmVwzZu6mMz7MRPEBYH/WitC/lP4jdtHqtHqKtPT+NXHzh2A/c"
            + "tl3nOSR5RnDKzL7kUVXheL2cES+41jZ1LBy9T3ZxXd59Tf8IdC1JJ24pHmzJ"
            + "KZNYxIr+rREvIxZsNvJI2urefS2/55AZCVC58hahjS4DWPzpxMkRb5xkL8L8"
            + "Yt8OikvdsazHuamTlh2tggCiQ3LDqXtG+sk67UZQycWis0vG6pd6S+E6K4Sn"
            + "mymsn/CbsSqr8rVd/JppqmYnPPmzkEw0oztNW2pNzfui+vvr6gFV81cWIdFt"
            + "TOWlXSzOAwm7/Dj8kSYyIxZVrHsRCbnSdkmP0timKpBkGN+CCHsibzl0RJHj"
            + "IIznWLUBCnwxUwLJCdo6qTZoOhegDYZFVgk4eExiL26XJjbLJj25tB+ITBiI"
            + "RwR52Mxf9zoX3V8I1OCnvznt0fE5NBTob0LDXoqGy1PlTJv+8DKrI4Vzgk9/"
            + "yDjMw/NJgimQS97cxU9CxnQO7FmCEnEeB/E9kniml5EGLEod3Ugf6ElcuADn"
            + "Kp4E1cijOiRdHPX6vnxjw0n0OHpOpaCf9ynWF5fVXNoAofqTB7nGMn1YPJUo"
            + "gl2pDlX6Z5dTZ1IyoOAxkOLTKH6ULY91wnPgC1k8LoOKAWJOtcdxBai+rxGe"
            + "Nw6pYsl6L0ViIBsVHOlg+JEFtVEhL9vUuv9NcqWu6swt/bV84rU993vPj1FR"
            + "bPasRjTBAIwJ4KVvQHtXg0bta8vWFIt7hOSjpKD+Fe8c59oZcmvmfCWo1yJE"
            + "YMGZETkP58SlGtVUMOXYZxEzLe1OG2icd8guZ4d/DeCLv6JuO2q958UdM1I6"
            + "yO8+1r1w6nzsTwaXZn0htKYbC8dYIl7jJK/5y/ITZWSJl5BbtoUXlVuz/GGx"
            + "vllOfG+H/iSr3wQ8Meue+9zh1l+gdH10dWlLCjot0ri8e/xKU9ZaRt6dlHka"
            + "c8Nh1U30ZrMBooXYBZmA/0+Ntz5WIEh6GQKeWV/ZwtOZdfGsYzC1L9t3Xknu"
            + "GxVjEfV1l7b9Fx5j5jElMCMGCSqGSIb3DQEJFTEWBBRFy/ERb7PziymEs8ci"
            + "TK5wp093iTAxMCEwCQYFKw4DAhoFAAQU1SGg9xV7jfLcJh3tzd+phZTMN38E"
            + "CL6WgCtEom7kAgIIAA==");

    private static byte[] rawKeyBagStore = Base64.decode("MIIFlgIBAzCCBY8GCSqGSIb3DQEHAaCCBYAEggV8MIIFeDCCAv4GCSqGSIb3DQEHAaCCAu8EggLrMIIC5zCCAuMGCyqGSIb3DQEMCgEBoIICejCCAnYCAQAwDQYJKoZIhvcNAQEBBQAEggJgMIICXAIBAAKBgQCF4Tw78b8eDuwY+FomQazkPFuAxDbWTs//AozC4MvzBatdJeDu+s9WyK3PdU+gI7wFish0r2FP8M5dj/rA0ieCJ9UDTGWVKm06DB0y7zmAO3SS/3TXGQRekMmOXBtVlZa4AYVy8Tr+Ls69gfo3sgqJU8uH0ebWuoQTKJz/mpst0wIDAQABAoGBAIJbpu/jWylkdEV4BSd9CWCO2LYP2CliQirXC8JxaoTuf0ZKrLNlqd+htYPsgSS3xstKsBbV8hYJrpbxq8J2npok973j0bm9sW9RL8XmAYJbaat27IzQQkGj2j4CNWPJzQC3NsDWQJPMJMFHvT1ZIj5ASwvOHwKpM6haLPxX24o5AkEA/zBVPpO6Ic9Yfd8Fk+BN/DykpPbLMUNZFl/I2MavoXTh5Ng7J4/S5ABxkvvQdqKf1Nhal5CznakU4BjFUGr+dwJBAIZOLwlfToFgekV4SmcPnq4aNGdetDfEettRGJLrKf+qrZrTzW3Rj6N2cjxKHsE5/xOpyjOtgVv3cTQm0x//VoUCQAdQBUFTzmOlo22H9Ir2RIXT3wvzHoN84JKpkAHWP7YquUZrg9ZwYqSx9o81tBWSN25L/NyXAu6jp7t8OjtBtaUCQCILB1k0001wCw4444MkLnCrK8VX+A56uzmEYNo8ybSIquCn91Zy3BnvGB24G/uWm9V8IEjhHf0Vx5gUj0d5DZECQGRs4BMYE+y2Tpn7/zbjhZh/iAdttDq5/b2BBMbSiosSKRIGkOyHTu0SJKoxoDnHA5ryLK8NoSwoGjID5qESjA8xVjAjBgkqhkiG9w0BCRUxFgQU3U3Taaj7rCAV2GyyVEnAUZvc4JkwLwYJKoZIhvcNAQkUMSIeIABPAE4AVgBJAEYAXwBUAGUAcwB0AF8AQQBsAGkAYQBzMIICcgYJKoZIhvcNAQcBoIICYwSCAl8wggJbMIICVwYLKoZIhvcNAQwKAQOgggHuMIIB6gYKKoZIhvcNAQkWAaCCAdoEggHWMIIB0jCCATugAwIBAgIICNurBKCCK6gwDQYJKoZIhvcNAQEFBQAwIDERMA8GA1UEAwwIT05WSUYgVFQxCzAJBgNVBAYTAlVTMCAXDTcwMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAgMREwDwYDVQQDDAhPTlZJRiBUVDELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIXhPDvxvx4O7Bj4WiZBrOQ8W4DENtZOz/8CjMLgy/MFq10l4O76z1bIrc91T6AjvAWKyHSvYU/wzl2P+sDSJ4In1QNMZZUqbToMHTLvOYA7dJL/dNcZBF6QyY5cG1WVlrgBhXLxOv4uzr2B+jeyColTy4fR5ta6hBMonP+amy3TAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEARmnQ9q/lUycK5P4shGFlwK0Uy3dHZs4VxOBSinejSTTy1FL4+SRzwA+YDMmfRrI0WHY/upUCYyugDj5kDg5K6/mSiIWGr0PDjl+8qw352fpUQgY4vnpGBaJoLQf/KRFilVhZJz0QDq5iHo16UkibDDHYQqdt6la5SHKx4U6AJwYxVjAjBgkqhkiG9w0BCRUxFgQU3U3Taaj7rCAV2GyyVEnAUZvc4JkwLwYJKoZIhvcNAQkUMSIeIABPAE4AVgBJAEYAXwBUAGUAcwB0AF8AQQBsAGkAYQBz");

    // Valid PKCS #12 File with SHA-256 HMAC and PRF
    private static final byte[] pkcs12WithPBMac1PBKdf2_a1 = Base64.decode(
        "MIIKigIBAzCCCgUGCSqGSIb3DQEHAaCCCfYEggnyMIIJ7jCCBGIGCSqGSIb3DQEH\n" +
            "BqCCBFMwggRPAgEAMIIESAYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTBKMCkGCSqG\n" +
            "SIb3DQEFDDAcBAg9pxXxY2yscwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQME\n" +
            "ASoEEK7yYaFQDi1pYwWzm9F/fs+AggPgFIT2XapyaFgDppdvLkdvaF3HXw+zjzKb\n" +
            "7xFC76DtVPhVTWVHD+kIss+jsj+XyvMwY0aCuAhAG/Dig+vzWomnsqB5ssw5/kTb\n" +
            "+TMQ5PXLkNeoBmB6ArKeGc/QmCBQvQG/a6b+nXSWmxNpP+71772dmWmB8gcSJ0kF\n" +
            "Fj75NrIbmNiDMCb71Q8gOzBMFf6BpXf/3xWAJtxyic+tSNETfOJa8zTZb0+lV0w9\n" +
            "5eUmDrPUpuxEVbb0KJtIc63gRkcfrPtDd6Ii4Zzbzj2Evr4/S4hnrQBsiryVzJWy\n" +
            "IEjaD0y6+DmG0JwMgRuGi1wBoGowi37GMrDCOyOZWC4n5wHLtYyhR6JaElxbrhxP\n" +
            "H46z2USLKmZoF+YgEQgYcSBXMgP0t36+XQocFWYi2N5niy02TnctwF430FYsQlhJ\n" +
            "Suma4I33E808dJuMv8T/soF66HsD4Zj46hOf4nWmas7IaoSAbGKXgIa7KhGRJvij\n" +
            "xM3WOX0aqNi/8bhnxSA7fCmIy/7opyx5UYJFWGBSmHP1pBHBVmx7Ad8SAsB9MSsh\n" +
            "nbGjGiUk4h0QcOi29/M9WwFlo4urePyI8PK2qtVAmpD3rTLlsmgzguZ69L0Q/CFU\n" +
            "fbtqsMF0bgEuh8cfivd1DYFABEt1gypuwCUtCqQ7AXK2nQqOjsQCxVz9i9K8NDeD\n" +
            "aau98VAl0To2sk3/VR/QUq0PRwU1jPN5BzUevhE7SOy/ImuJKwpGqqFljYdrQmj5\n" +
            "jDe+LmYH9QGVRlfN8zuU+48FY8CAoeBeHn5AAPml0PYPVUnt3/jQN1+v+CahNVI+\n" +
            "La8q1Nen+j1R44aa2I3y/pUgtzXRwK+tPrxTQbG030EU51LYJn8amPWmn3w75ZIA\n" +
            "MJrXWeKj44de7u4zdUsEBVC2uM44rIHM8MFjyYAwYsey0rcp0emsaxzar+7ZA67r\n" +
            "lDoXvvS3NqsnTXHcn3T9tkPRoee6L7Dh3x4Od96lcRwgdYT5BwyH7e34ld4VTUmJ\n" +
            "bDEq7Ijvn4JKrwQJh1RCC+Z/ObfkC42xAm7G010u3g08xB0Qujpdg4a7VcuWrywF\n" +
            "c7hLNquuaF4qoDaVwYXHH3iuX6YlJ/3siTKbYCVXPEZOAMBP9lF/OU76UMJBQNfU\n" +
            "0xjDx+3AhUVgnGuCsmYlK6ETDp8qOZKGyV0KrNSGtqLx3uMhd7PETeW+ML3tDQ/0\n" +
            "X9fMkcZHi4C2fXnoHV/qa2dGhBj4jjQ0Xh1poU6mxGn2Mebe2hDsBZkkBpnn7pK4\n" +
            "wP/VqXdQTwqEuvzGHLVFsCuADe40ZFBmtBrf70wG7ZkO8SUZ8Zz1IX3+S024g7yj\n" +
            "QRev/6x6TtkwggWEBgkqhkiG9w0BBwGgggV1BIIFcTCCBW0wggVpBgsqhkiG9w0B\n" +
            "DAoBAqCCBTEwggUtMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhTxzw+\n" +
            "VptrYAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEK9nSqc1I2t4tMVG\n" +
            "bWHpdtQEggTQzCwI7j34gCTvfj6nuOSndAjShGv7mN2j7WMV0pslTpq2b9Bn3vn1\n" +
            "Y0JMvL4E7sLrUzNU02pdOcfCnEpMFccNv2sQrLp1mOCKxu8OjSqHZLoKVL0ROVsZ\n" +
            "8dMECLLigDlPKRiSyLErl14tErX4/zbkUaWMROO28kFbTbubQ8YoHlRUwsKW1xLg\n" +
            "vfi0gRkG/zHXRfQHjX/8NStv7hXlehn7/Gy2EKPsRFhadm/iUHAfmCMkMgHTU248\n" +
            "JER9+nsXltd59H+IeDpj/kbxZ+YvHow9XUZKu828d3MQnUpLZ1BfJGhMBPVwbVUD\n" +
            "A40CiQBVdCoGtPJyalL28xoS3H0ILFCnwQOr6u0HwleNJPGHq78HUyH6Hwxnh0b0\n" +
            "5o163r6wTFZn5cMOxpbs/Ttd+3TrxmrYpd2XnuRme3cnaYJ0ILvpc/8eLLR7SKjD\n" +
            "T4JhZ0h/CfcV2WWvhpQugkY0pWrZ+EIMneB1dZB96mJVLxOi148OeSgi0PsxZMNi\n" +
            "YM33rTpwQT5WqOsEyDwUQpne5b8Kkt/s7EN0LJNnPyJJRL1LcqOdr6j+6YqRtPa7\n" +
            "a9oWJqMcuTP+bqzGRJh+3HDlFBw2Yzp9iadv4KmB2MzhStLUoi2MSjvnnkkd5Led\n" +
            "sshAd6WbKfF7kLAHQHT4Ai6dMEO4EKkEVF9JBtxCR4JEn6C98Lpg+Lk+rfY7gHOf\n" +
            "ZxtgGURwgXRY3aLUrdT55ZKgk3ExVKPzi5EhdpAau7JKhpOwyKozAp/OKWMNrz6h\n" +
            "obu2Mbn1B+IA60psYHHxynBgsJHv7WQmbYh8HyGfHgVvaA8pZCYqxxjpLjSJrR8B\n" +
            "Bu9H9xkTh7KlhxgreXYv19uAYbUd95kcox9izad6VPnovgFSb+Omdy6PJACPj6hF\n" +
            "W6PJbucP0YPpO0VtWtQdZZ3df1P0hZ7qvKwOPFA+gKZSckgqASfygiP9V3Zc8jIi\n" +
            "wjNzoDM2QT+UUJKiiGYXJUEOO9hxzFHlGj759DcNRhpgl5AgR57ofISD9yBuCAJY\n" +
            "PQ/aZHPFuRTrcVG3RaIbCAS73nEznKyFaLOXfzyfyaSmyhsH253tnyL1MejC+2bR\n" +
            "Eko/yldgFUxvU5JI+Q3KJ6Awj+PnduHXx71E4UwSuu2xXYMpxnQwI6rroQpZBX82\n" +
            "HhqgcLV83P8lpzQwPdHjH5zkoxmWdC0+jU/tcQfNXYpJdyoaX7tDmVclLhwl9ps/\n" +
            "O841pIsNLJWXwvxG6B+3LN/kw4QjwN194PopiOD7+oDm5mhttO78CrBrRxHMD/0Q\n" +
            "qniZjKzSZepxlZq+J792u8vtMnuzzChxu0Bf3PhIXcJNcVhwUtr0yKe/N+NvC0tm\n" +
            "p8wyik/BlndxN9eKbdTOi2wIi64h2QG8nOk66wQ/PSIJYwZl6eDNEQSzH/1mGCfU\n" +
            "QnUT17UC/p+Qgenf6Auap2GWlvsJrB7u/pytz65rtjt/ouo6Ih6EwWqwVVpGXZD0\n" +
            "7gVWH0Ke/Vr6aPGNvkLcmftPuDZsn9jiig3guhdeyRVf10Ox369kKWcG75q77hxE\n" +
            "IzSzDyUlBNbnom9SIjut3r+qVYmWONatC6q/4D0I42Lnjd3dEyZx7jmH3g/S2ASM\n" +
            "FzWr9pvXc61dsYOkdZ4PYa9XPUZxXFagZsoS3F1sU799+IJVU0tC0MExJTAjBgkq\n" +
            "hkiG9w0BCRUxFgQUwWO5DorvVWYF3BWUmAw0rUEajScwfDBtMEkGCSqGSIb3DQEF\n" +
            "DjA8MCwGCSqGSIb3DQEFDDAfBAhvRzw4sC4xcwICCAACASAwDAYIKoZIhvcNAgkF\n" +
            "ADAMBggqhkiG9w0CCQUABCB6pW2FOdcCNj87zS64NUXG36K5aXDnFHctIk5Bf4kG\n" +
            "3QQITk9UIFVTRUQCAQE=\n");

    // Valid PKCS #12 File with SHA-256 HMAC and SHA-512 PRF
    private static final byte[] pkcs12WithPBMac1PBKdf2_a2 = Base64.decode("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\n" +
        "6QQITk9UIFVTRUQCAQE=");

    // Valid PKCS #12 File with SHA-512 HMAC and PRF
    private static final byte[] pkcs12WithPBMac1PBKdf2_a3 = Base64.decode("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");

    // Invalid PKCS #12 File with Incorrect Iteration Count
    private static final byte[] pkcs12WithPBMac1PBKdf2_a4 = Base64.decode("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\n" +
        "3QQITk9UIFVTRUQCAggA");

    // Invalid PKCS #12 File with Incorrect Salt
    private static final byte[] pkcs12WithPBMac1PBKdf2_a5 = Base64.decode("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\n" +
        "3QQIb0c8OLAuMXMCAQE=");

    // Invalid PKCS #12 File with Missing Key Length
    private static final byte[] pkcs12WithPBMac1PBKdf2_a6 = Base64.decode("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\n" +
        "b0c8OLAuMXMCAggA");
    
    /**
     * we generate a self signed certificate for the sake of testing - RSA
     */
    public Certificate createCert(
        PublicKey pubKey,
        PrivateKey privKey,
        String issuerEmail,
        String subjectEmail)
        throws Exception
    {
        //
        // distinguished name table.
        //
        X500NameBuilder issuerBldr = new X500NameBuilder();

        issuerBldr.addRDN(BCStyle.C, "AU");
        issuerBldr.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        issuerBldr.addRDN(BCStyle.L, "Melbourne");
        issuerBldr.addRDN(BCStyle.ST, "Victoria");
        issuerBldr.addRDN(BCStyle.EmailAddress, issuerEmail);

        X500NameBuilder subjectBldr = new X500NameBuilder();

        subjectBldr.addRDN(BCStyle.C, "AU");
        subjectBldr.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        subjectBldr.addRDN(BCStyle.L, "Melbourne");
        subjectBldr.addRDN(BCStyle.ST, "Victoria");
        subjectBldr.addRDN(BCStyle.EmailAddress, subjectEmail);

        return TestUtils.createCert(issuerBldr.build(), privKey, subjectBldr.build(), "SHA1withRSA", null, pubKey);
    }

    private void testCertsOnly()
        throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(certsOnly), null);

        isTrue(pkcs12.containsAlias("alias"));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        pkcs12.store(bOut, null);

        pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(bOut.toByteArray()), null);

        isTrue(pkcs12.containsAlias("alias"));

        pkcs12.load(new ByteArrayInputStream(certsOnly), new char[]{});

        isTrue(pkcs12.containsAlias("alias"));

        try
        {
            pkcs12.load(new ByteArrayInputStream(certsOnly), "1".toCharArray());
            fail("no exception");
        }
        catch (IOException e)
        {
            isEquals("password supplied for keystore that does not require one", e.getMessage());
        }

        System.setProperty("org.bouncycastle.pkcs12.ignore_useless_passwd", "true");

        pkcs12.load(new ByteArrayInputStream(certsOnly), "1".toCharArray());

        System.setProperty("org.bouncycastle.pkcs12.ignore_useless_passwd", "false");
    }

    private void testGOSTStore()
        throws Exception
    {
        byte[] data = Hex.decode("deadbeef");

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(gostPfx), "1".toCharArray());

        PrivateKey pk = (PrivateKey)pkcs12.getKey("cp_exported", null);
        Certificate[] pubCerts = pkcs12.getCertificateChain("cp_exported");

        Signature sig = Signature.getInstance("ECGOST3410", BC);

        sig.initSign(pk);

        sig.update(data);

        byte[] signature = sig.sign();

        sig = Signature.getInstance("ECGOST3410", BC);

        sig.initVerify(pubCerts[0].getPublicKey());

        sig.update(data);

        if (!sig.verify(signature))
        {
            fail("key test failed in GOST store");
        }

        KeyStore ks = KeyStore.getInstance("PKCS12", BC);

        ks.load(new ByteArrayInputStream(gostOpenSSLIntegerDPfx), "password".toCharArray());

        PrivateKey key = (PrivateKey)ks.getKey("test", "password".toCharArray());

        X509Certificate cert = (X509Certificate)ks.getCertificate("test");

        sig.initSign(key);

        sig.update(data);

        signature = sig.sign();

        sig.initVerify(cert.getPublicKey());

        sig.update(data);

        if (!sig.verify(signature))
        {
            fail("key test failed in 2nd GOST store");
        }

        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        pkcs12.store(stream, "2".toCharArray());

        // confirm mac details consistent
        Pfx bag = Pfx.getInstance(stream.toByteArray());
        MacData mData = bag.getMacData();

        isEquals("mac alg not match", new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411, DERNull.INSTANCE), mData.getMac().getAlgorithmId());
        isEquals(2048, mData.getIterationCount().intValue());
        isEquals(8, mData.getSalt().length);

        //confirm key recovery
        pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(stream.toByteArray()), "2".toCharArray());

        PrivateKey pk2 = (PrivateKey)pkcs12.getKey("cp_exported", null);

        isEquals(pk, pk2);
    }

    private void testDilithiumStore()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair kp = kpg.generateKeyPair();

        Certificate cert = TestUtils.createSelfSignedCert("CN=Dilithium Test", "ML-DSA-65", kp);

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(null, null);

        pkcs12.setKeyEntry("test", kp.getPrivate(), new char[0], new Certificate[]{cert});

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        pkcs12.store(bOut, "hello".toCharArray());

        pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(bOut.toByteArray()), "hello".toCharArray());

        Key key = pkcs12.getKey("test", new char[0]);

        isEquals(key, kp.getPrivate());

        Certificate[] certs = pkcs12.getCertificateChain("test");

        certs[0].verify(certs[0].getPublicKey());
    }

    private void testRawKeyBagStore()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(new ByteArrayInputStream(rawKeyBagStore), null);

        isTrue(store.isKeyEntry("ONVIF_Test_Alias"));
    }

    private void testNTRUStore()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BC");

        kpg.initialize(FalconParameterSpec.falcon_512);

        KeyPair skp = kpg.generateKeyPair();

        kpg = KeyPairGenerator.getInstance("NTRU", "BC");

        kpg.initialize(NTRUParameterSpec.ntruhrss701);

        KeyPair kp = kpg.generateKeyPair();

        Certificate cert = TestUtils.createCert(new X500Name("CN=Falcon Signer"), skp.getPrivate(), new X500Name("CN=NTRU Key"), "Falcon-512", null, kp.getPublic());

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(null, null);

        pkcs12.setKeyEntry("test", kp.getPrivate(), new char[0], new Certificate[]{cert});

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        pkcs12.store(bOut, "hello".toCharArray());

        pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(bOut.toByteArray()), "hello".toCharArray());

        Key key = pkcs12.getKey("test", new char[0]);

        isEquals(key, kp.getPrivate());

        Certificate[] certs = pkcs12.getCertificateChain("test");

        certs[0].verify(skp.getPublic());

        isEquals(certs[0].getPublicKey(), kp.getPublic());
    }

    private void testFalconStore()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BC");

        kpg.initialize(FalconParameterSpec.falcon_512);

        KeyPair kp = kpg.generateKeyPair();

        Certificate cert = TestUtils.createSelfSignedCert("CN=Falcon Test", "Falcon-512", kp);

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(null, null);

        pkcs12.setKeyEntry("test", kp.getPrivate(), new char[0], new Certificate[]{cert});

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        pkcs12.store(bOut, "hello".toCharArray());

        pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(bOut.toByteArray()), "hello".toCharArray());

        Key key = pkcs12.getKey("test", new char[0]);

        isEquals(key, kp.getPrivate());

        Certificate[] certs = pkcs12.getCertificateChain("test");

        certs[0].verify(certs[0].getPublicKey());
    }

    private void testSphincsPlusStore()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCS+", "BC");

        kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f_robust);

        KeyPair kp = kpg.generateKeyPair();

        Certificate cert = TestUtils.createSelfSignedCert("CN=SphincsPlus Test", "SPHINCS+", kp);

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(null, null);

        pkcs12.setKeyEntry("test", kp.getPrivate(), new char[0], new Certificate[]{cert});

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        pkcs12.store(bOut, "hello".toCharArray());

        pkcs12 = KeyStore.getInstance("PKCS12", BC);

        pkcs12.load(new ByteArrayInputStream(bOut.toByteArray()), "hello".toCharArray());

        Key key = pkcs12.getKey("test", new char[0]);

        isEquals(key, kp.getPrivate());

        Certificate[] certs = pkcs12.getCertificateChain("test");

        certs[0].verify(certs[0].getPublicKey());
    }

    public void testPKCS12StoreFriendlyName()
        throws Exception
    {
        byte[] storeBytes = Base64.decode("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");
        char[] storePassword = "Axw9eE51lKEx0IuqHbzlJ+sx".toCharArray();
        ByteArrayInputStream stream = new ByteArrayInputStream(storeBytes);

        KeyStore store1 = KeyStore.getInstance("PKCS12", BC);
        store1.load(stream, storePassword);

        // overwriteFriendlyName=FALSE AND friendlyName is null -> friendlyName should stay null
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PKCS12StoreParameter storeParameter = new PKCS12StoreParameter(outStream, storePassword, false, false);
        store1.store(storeParameter);

        byte[] outBytes = outStream.toByteArray();
        stream = new ByteArrayInputStream(outBytes);
        KeyStore store2 = KeyStore.getInstance("PKCS12", BC);
        store2.load(stream, storePassword);

        String alias1 = store1.aliases().nextElement();
        String alias2 = store2.aliases().nextElement();
        PKCS12BagAttributeCarrier cert2 = (PKCS12BagAttributeCarrier)store2.getCertificate(alias2);

        if (cert2.hasFriendlyName())
        {
            fail("with overwriteFriendlyName=false, default friendlyName should not be written to new store");
        }

        // overwriteFriendlyName=FALSE AND friendlyName is null -> friendlyName should be default value
        outStream = new ByteArrayOutputStream();
        storeParameter = new PKCS12StoreParameter(outStream, storePassword, false, true);
        store1.store(storeParameter);

        outBytes = outStream.toByteArray();
        stream = new ByteArrayInputStream(outBytes);
        store2.load(stream, storePassword);

        alias1 = store1.aliases().nextElement();
        alias2 = store2.aliases().nextElement();
        cert2 = (PKCS12BagAttributeCarrier)store2.getCertificate(alias2);

        if (!cert2.hasFriendlyName())
        {
            fail("with overwriteFriendlyName=true, default friendlyName should be written to new store");
        }

        // Add custom friendlyName to store1
        if (store1.isKeyEntry(alias1))
        {
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)store1.getEntry(alias1, new KeyStore.PasswordProtection(storePassword));
            ((PKCS12BagAttributeCarrier)pkEntry.getCertificate()).setFriendlyName("my_custom_friendly_name");
            ((PKCS12BagAttributeCarrier)pkEntry.getPrivateKey()).setFriendlyName("my_custom_friendly_name");
        }
        else
        {
            KeyStore.TrustedCertificateEntry entry = (KeyStore.TrustedCertificateEntry)store1.getEntry(alias1, null);
            ((PKCS12BagAttributeCarrier)entry.getTrustedCertificate()).setFriendlyName("my_custom_friendly_name");
        }

        // overwriteFriendlyName=TRUE AND friendlyName is null then added -> friendlyName should be default value
        outStream = new ByteArrayOutputStream();
        storeParameter = new PKCS12StoreParameter(outStream, storePassword, false, true);
        store1.store(storeParameter);

        outBytes = outStream.toByteArray();
        stream = new ByteArrayInputStream(outBytes);
        store2.load(stream, storePassword);

        alias1 = store1.aliases().nextElement();
        alias2 = store2.aliases().nextElement();

        if (alias2.equals("my_custom_friendly_name"))
        {
            fail("with overwriteFriendlyName=true, default friendlyName should be written to new store");
        }

        // overwriteFriendlyName=FALSE AND friendlyName is null then added -> friendlyName should be added value
        // Add custom friendlyName to store1
        if (store1.isKeyEntry(alias1))
        {
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)store1.getEntry(alias1, new KeyStore.PasswordProtection(storePassword));
            ((PKCS12BagAttributeCarrier)pkEntry.getCertificate()).setFriendlyName("my_custom_friendly_name");
            ((PKCS12BagAttributeCarrier)pkEntry.getPrivateKey()).setFriendlyName("my_custom_friendly_name");
        }
        else
        {
            KeyStore.TrustedCertificateEntry entry = (KeyStore.TrustedCertificateEntry)store1.getEntry(alias1, null);
            ((PKCS12BagAttributeCarrier)entry.getTrustedCertificate()).setFriendlyName("my_custom_friendly_name");
        }

        outStream = new ByteArrayOutputStream();
        storeParameter = new PKCS12StoreParameter(outStream, storePassword, false, false);
        store1.store(storeParameter);

        outBytes = outStream.toByteArray();
        stream = new ByteArrayInputStream(outBytes);
        store2.load(stream, storePassword);

        alias2 = store2.aliases().nextElement();

        if (!alias2.equals("my_custom_friendly_name"))
        {
            fail("with overwriteFriendlyName=false, added friendlyName should be written to new store");
        }
    }

    public void testPKCS12Store()
        throws Exception
    {
        BigInteger mod = new BigInteger("bb1be8074e4787a8d77967f1575ef72dd7582f9b3347724413c021beafad8f32dba5168e280cbf284df722283dad2fd4abc750e3d6487c2942064e2d8d80641aa5866d1f6f1f83eec26b9b46fecb3b1c9856a303148a5cc899c642fb16f3d9d72f52526c751dc81622c420c82e2cfda70fe8d13f16cc7d6a613a5b2a2b5894d1", 16);
        KeyStore store = KeyStore.getInstance("PKCS12", BC);
        ByteArrayInputStream stream = new ByteArrayInputStream(pkcs12);

        store.load(stream, passwd);

        Enumeration en = store.aliases();
        String pName = null;

        while (en.hasMoreElements())
        {
            String n = (String)en.nextElement();
            if (store.isKeyEntry(n))
            {
                pName = n;
            }
            else
            {
                // the store's we're using here are consistent so this test will pass - it's actually
                // possible for this test to fail in other circumstances as PKCS#12 allows certificates
                // to be stored multiple times under different aliases.
                X509Certificate cert = (X509Certificate)store.getCertificate(n);

                if (!store.getCertificateAlias(cert).equals(n))
                {
                    fail("certificate alias check fails");
                }
            }
        }

        PrivateKey key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        Certificate[] ch = store.getCertificateChain(pName);

        if (ch.length != 3)
        {
            fail("chain was wrong length");
        }

        if (!((X509Certificate)ch[0]).getSerialNumber().equals(new BigInteger("96153094170511488342715101755496684211")))
        {
            fail("chain[0] wrong certificate.");
        }

        if (!((X509Certificate)ch[1]).getSerialNumber().equals(new BigInteger("279751514312356623147411505294772931957")))
        {
            fail("chain[1] wrong certificate.");
        }

        if (!((X509Certificate)ch[2]).getSerialNumber().equals(new BigInteger("11341398017")))
        {
            fail("chain[2] wrong certificate.");
        }

        //
        // save test
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        stream = new ByteArrayInputStream(bOut.toByteArray());

        store.load(stream, passwd);

        key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        //
        // save test using LoadStoreParameter
        //
        bOut = new ByteArrayOutputStream();

        PKCS12StoreParameter storeParam = new PKCS12StoreParameter(bOut, passwd, true);

        store.store(storeParam);

        byte[] data = bOut.toByteArray();

        stream = new ByteArrayInputStream(data);
        store.load(stream, passwd);

        key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        ASN1Encodable outer = new ASN1StreamParser(data).readObject();
        if (!(outer instanceof DLSequenceParser))
        {
            fail("Failed DER encoding test.");
        }


        //
        // save test using LoadStoreParameter  - old version
        //
        bOut = new ByteArrayOutputStream();

        storeParam = new org.bouncycastle.jcajce.provider.config.PKCS12StoreParameter(bOut, passwd, true);

        store.store(storeParam);

        data = bOut.toByteArray();

        stream = new ByteArrayInputStream(data);
        store.load(stream, passwd);

        key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        outer = new ASN1StreamParser(data).readObject();
        if (!(outer instanceof DLSequenceParser))
        {
            fail("Failed DER encoding test.");
        }

        //
        // save test using LoadStoreParameter
        //
        bOut = new ByteArrayOutputStream();

        JDKPKCS12StoreParameter oldParam = new JDKPKCS12StoreParameter();
        oldParam.setOutputStream(bOut);
        oldParam.setPassword(passwd);
        oldParam.setUseDEREncoding(true);

        store.store(oldParam);

        data = bOut.toByteArray();

        stream = new ByteArrayInputStream(data);
        store.load(stream, passwd);

        key = (PrivateKey)store.getKey(pName, null);

        if (!((RSAPrivateKey)key).getModulus().equals(mod))
        {
            fail("Modulus doesn't match.");
        }

        outer = new ASN1StreamParser(data).readObject();
        if (!(outer instanceof DLSequenceParser))
        {
            fail("Failed DER encoding test.");
        }

        //
        // delete test
        //
        store.deleteEntry(pName);

        if (store.getKey(pName, null) != null)
        {
            fail("Failed deletion test.");
        }

        // cert chain test
        //
        store.setCertificateEntry("testCert", ch[2]);

        if (store.getCertificateChain("testCert") != null)
        {
            fail("Failed null chain test.");
        }

        //
        // UTF 8 single cert test
        //
        store = KeyStore.getInstance("PKCS12", BC);
        stream = new ByteArrayInputStream(certUTF);

        store.load(stream, "user".toCharArray());

        if (store.getCertificate("37") == null)
        {
            fail("Failed to find UTF cert.");
        }

        //
        // try for a self generated certificate
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // set up the keys
        //
        PrivateKey privKey = null;
        PublicKey pubKey = null;

        try
        {
            KeyFactory fact = KeyFactory.getInstance("RSA", BC);

            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
        }

        Certificate[] chain = new Certificate[1];

        chain[0] = createCert(pubKey, privKey, "issuer@bouncycastle.org", "subject@bouncycastle.org");

        testSupportedTypes(privKey, chain);

        store = KeyStore.getInstance("PKCS12", BC);

        store.load(null, null);

        store.setKeyEntry("privateKey", privKey, null, chain);

        if (!store.containsAlias("privateKey") || !store.containsAlias("PRIVATEKEY"))
        {
            fail("couldn't find alias privateKey");
        }

        if (store.isCertificateEntry("privateKey"))
        {
            fail("key identified as certificate entry");
        }

        if (!store.isKeyEntry("privateKey") || !store.isKeyEntry("PRIVATEKEY"))
        {
            fail("key not identified as key entry");
        }

        if (!"privateKey".equals(store.getCertificateAlias(chain[0])))
        {
            fail("Did not return alias for key certificate privateKey");
        }

        KeyPair kp2 = TestUtils.generateRSAKeyPair();
        KeyPair kp2ca = TestUtils.generateRSAKeyPair();
        KeyPair kp2ee = TestUtils.generateRSAKeyPair();
        KeyPair kp3ee = TestUtils.generateRSAKeyPair();

        X509Certificate kp2Root = TestUtils.generateRootCert(kp2, new X500Name("CN=KP2 ROOT"));
        X509Certificate kp2CA = TestUtils.generateIntermediateCert(kp2ca.getPublic(), new X500Name("CN=KP2 CA"), kp2.getPrivate(), kp2Root);
        X509Certificate kp2EE = TestUtils.generateEndEntityCert(kp2ee.getPublic(), new X500Name("CN=KP2 EE"), KeyPurposeId.id_kp_codeSigning, kp2ca.getPrivate(), kp2CA);
        X509Certificate kp3EE = TestUtils.generateEndEntityCert(kp3ee.getPublic(), new X500Name("CN=KP3 EE"), KeyPurposeId.id_kp_capwapAC, KeyPurposeId.id_kp_capwapWTP, kp2ca.getPrivate(), kp2CA);

        store.setCertificateEntry("kp2Root", kp2Root);       // should have any key usage
        store.setCertificateEntry("kp2EE", kp2EE);
        store.setCertificateEntry("kp3EE", kp3EE);

        ByteArrayOutputStream store1Stream = new ByteArrayOutputStream();

        store.store(store1Stream, passwd);

        testNoExtraLocalKeyID(store1Stream.toByteArray());

        // trusted key entry test
        store = KeyStore.getInstance("PKCS12", BC);

        store.load(new ByteArrayInputStream(store1Stream.toByteArray()), passwd);

        PKCS12BagAttributeCarrier usage1 = (PKCS12BagAttributeCarrier)store.getCertificate("kp2Root");

        ASN1Encodable keyUsageValue1 = usage1.getBagAttribute(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage);

        isEquals(KeyPurposeId.anyExtendedKeyUsage, keyUsageValue1);

        PKCS12BagAttributeCarrier usage2 = (PKCS12BagAttributeCarrier)store.getCertificate("kp2EE");

        ASN1Encodable keyUsageValue2 = usage2.getBagAttribute(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage);

        isEquals(KeyPurposeId.id_kp_codeSigning, keyUsageValue2);

        PKCS12BagAttributeCarrier usage3 = (PKCS12BagAttributeCarrier)store.getCertificate("kp3EE");

        ASN1Encodable keyUsageValue3 = usage3.getBagAttribute(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage);

        isEquals(new DERSet(new ASN1Encodable[]{KeyPurposeId.id_kp_capwapAC, KeyPurposeId.id_kp_capwapWTP}), keyUsageValue3);

        //
        // no friendly name test
        //
        store = KeyStore.getInstance("PKCS12", BC);
        stream = new ByteArrayInputStream(pkcs12noFriendly);

        store.load(stream, noFriendlyPassword);

        en = store.aliases();
        pName = null;

        while (en.hasMoreElements())
        {
            String n = (String)en.nextElement();

            if (store.isKeyEntry(n))
            {
                pName = n;
            }
        }

        ch = store.getCertificateChain(pName);

        for (int i = 0; i != ch.length; i++)
        {
            //System.out.println(ch[i]);
        }

        if (ch.length != 1)
        {
            fail("no cert found in pkcs12noFriendly");
        }

        //
        // failure tests
        //
        ch = store.getCertificateChain("dummy");

        store.getCertificateChain("DUMMY");

        store.getCertificate("dummy");

        store.getCertificate("DUMMY");

        //
        // storage test
        //
        store = KeyStore.getInstance("PKCS12", BC);
        stream = new ByteArrayInputStream(pkcs12StorageIssue);

        store.load(stream, storagePassword);

        en = store.aliases();
        pName = null;

        while (en.hasMoreElements())
        {
            String n = (String)en.nextElement();

            if (store.isKeyEntry(n))
            {
                pName = n;
            }
        }

        ch = store.getCertificateChain(pName);
        if (ch.length != 2)
        {
            fail("Certificate chain wrong length");
        }

        store.store(new ByteArrayOutputStream(), storagePassword);

        //
        // basic certificate check
        //
        store.setCertificateEntry("cert", ch[1]);

        if (!store.containsAlias("cert") || !store.containsAlias("CERT"))
        {
            fail("couldn't find alias cert");
        }

        if (!store.isCertificateEntry("cert") || !store.isCertificateEntry("CERT"))
        {
            fail("cert not identified as certificate entry");
        }

        if (store.isKeyEntry("cert") || store.isKeyEntry("CERT"))
        {
            fail("cert identified as key entry");
        }

        if (!store.entryInstanceOf("cert", KeyStore.TrustedCertificateEntry.class))
        {
            fail("cert not identified as TrustedCertificateEntry");
        }

        if (!store.entryInstanceOf("CERT", KeyStore.TrustedCertificateEntry.class))
        {
            fail("CERT not identified as TrustedCertificateEntry");
        }

        if (store.entryInstanceOf("cert", KeyStore.PrivateKeyEntry.class))
        {
            fail("cert identified as key entry via PrivateKeyEntry");
        }

        if (!"cert".equals(store.getCertificateAlias(ch[1])))
        {
            fail("Did not return alias for certificate entry");
        }

        //
        // test restoring of a certificate with private key originally as a ca certificate
        //
        store = KeyStore.getInstance("PKCS12", BC);

        store.load(null, null);

        store.setCertificateEntry("cert", ch[0]);

        if (!store.containsAlias("cert") || !store.containsAlias("CERT"))
        {
            fail("restore: couldn't find alias cert");
        }

        if (!store.isCertificateEntry("cert") || !store.isCertificateEntry("CERT"))
        {
            fail("restore: cert not identified as certificate entry");
        }

        if (store.isKeyEntry("cert") || store.isKeyEntry("CERT"))
        {
            fail("restore: cert identified as key entry");
        }

        if (store.entryInstanceOf("cert", KeyStore.PrivateKeyEntry.class))
        {
            fail("restore: cert identified as key entry via PrivateKeyEntry");
        }

        if (store.entryInstanceOf("CERT", KeyStore.PrivateKeyEntry.class))
        {
            fail("restore: cert identified as key entry via PrivateKeyEntry");
        }

        if (!store.entryInstanceOf("cert", KeyStore.TrustedCertificateEntry.class))
        {
            fail("restore: cert not identified as TrustedCertificateEntry");
        }

        //
        // test of reading incorrect zero-length encoding
        //
        store = KeyStore.getInstance("PKCS12", BC);
        stream = new ByteArrayInputStream(pkcs12nopass);

        store.load(stream, "".toCharArray());
    }

    private void testSupportedTypes(PrivateKey privKey, Certificate[] chain)
        throws Exception
    {
        basicStoreTest(privKey, chain, "PKCS12");
        basicStoreTest(privKey, chain, "BCPKCS12");
        basicStoreTest(privKey, chain, "PKCS12-DEF");

        basicStoreTest(privKey, chain, "PKCS12-3DES-40RC2");
        basicStoreTest(privKey, chain, "PKCS12-3DES-3DES");

        basicStoreTest(privKey, chain, "PKCS12-DEF-3DES-40RC2");
        basicStoreTest(privKey, chain, "PKCS12-DEF-3DES-3DES");
    }

    private void basicStoreTest(PrivateKey privKey, Certificate[] chain, String type)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance(type, BC);

        store.load(null, null);

        store.setKeyEntry("key", privKey, null, chain);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        store.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        Key k = store.getKey("key", null);

        if (!k.equals(privKey))
        {
            fail("private key didn't match");
        }

        Certificate[] c = store.getCertificateChain("key");

        if (c.length != chain.length || !c[0].equals(chain[0]))
        {
            fail("certificates didn't match");
        }

        if (type.contains("DEF"))
        {
            if (c[0] instanceof X509CertificateObject)
            {
                fail("wrong certificate type found");
            }
        }

        // check attributes
        PKCS12BagAttributeCarrier b1 = (PKCS12BagAttributeCarrier)k;
        PKCS12BagAttributeCarrier b2 = (PKCS12BagAttributeCarrier)chain[0];

        if (b1.getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName) != null)
        {
            ASN1BMPString name = (ASN1BMPString)b1.getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName);

            if (!name.equals(new DERBMPString("key")))
            {
                fail("friendly name wrong");
            }
        }
        else
        {
            fail("no friendly name found on key");
        }

        if (b1.getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId) != null)
        {
            ASN1OctetString id = (ASN1OctetString)b1.getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId);

            if (!id.equals(b2.getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)))
            {
                fail("local key id mismatch");
            }
        }
        else
        {
            fail("no local key id found");
        }

        //
        // check algorithm types.
        //
        ASN1InputStream aIn = new ASN1InputStream(bOut.toByteArray());

        Pfx pfx = Pfx.getInstance(aIn.readObject());

        ContentInfo cInfo = pfx.getAuthSafe();

        ASN1OctetString auth = (ASN1OctetString)cInfo.getContent();

        aIn = new ASN1InputStream(auth.getOctets());
        ASN1Sequence s1 = (ASN1Sequence)aIn.readObject();

        ContentInfo c1 = ContentInfo.getInstance(s1.getObjectAt(0));
        ContentInfo c2 = ContentInfo.getInstance(s1.getObjectAt(1));

        aIn = new ASN1InputStream(((ASN1OctetString)c1.getContent()).getOctets());

        SafeBag sb = SafeBag.getInstance((((ASN1Sequence)aIn.readObject()).getObjectAt(0)));

        EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfo.getInstance(sb.getBagValue());

        if (!encInfo.getEncryptionAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC))
        {
            fail("key encryption algorithm wrong");
        }

        // check the key encryption

        // check the certificate encryption
        EncryptedData cb = EncryptedData.getInstance(c2.getContent());

        if (type.endsWith("3DES"))
        {
            if (!cb.getEncryptionAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC))
            {
                fail("expected 3DES found: " + cb.getEncryptionAlgorithm().getAlgorithm());
            }
        }
        else if (type.endsWith("40RC2"))
        {
            if (!cb.getEncryptionAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC))
            {
                fail("expected 40 bit RC2 found: " + cb.getEncryptionAlgorithm().getAlgorithm());
            }
        }
        else
        {
            if (!cb.getEncryptionAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC))
            {
                fail("expected 40 bit RC2 found: " + cb.getEncryptionAlgorithm().getAlgorithm());
            }
        }
    }

    private void testNoExtraLocalKeyID(byte[] store1data)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);

        kpg.initialize(512);

        KeyPair newPair = kpg.genKeyPair();

        KeyStore store1 = KeyStore.getInstance("PKCS12", BC);

        store1.load(new ByteArrayInputStream(store1data), passwd);

        KeyStore store2 = KeyStore.getInstance("PKCS12", BC);

        store2.load(null, null);

        PrivateKey k1 = (PrivateKey)store1.getKey("privatekey", null);
        Certificate[] chain1 = store1.getCertificateChain("privatekey");

        Certificate[] chain2 = new Certificate[chain1.length + 1];

        System.arraycopy(chain1, 0, chain2, 1, chain1.length);

        chain2[0] = createCert(newPair.getPublic(), k1, "subject@bouncycastle.org", "extra@bouncycaste.org");

        if (((PKCS12BagAttributeCarrier)chain1[0]).getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId) == null)
        {
            fail("localKeyID not found initially");
        }

        store2.setKeyEntry("new", newPair.getPrivate(), null, chain2);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        store2.store(bOut, passwd);

        store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        chain2 = store2.getCertificateChain("new");

        if (((PKCS12BagAttributeCarrier)chain2[1]).getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId) != null)
        {
            fail("localKeyID found after save");
        }
    }

    private void testChainCycle()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);

        // initialize key store
        keyStore.load(new ByteArrayInputStream(certChainCycle), "test".toCharArray());

        keyStore.getEntry("cycle", new KeyStore.PasswordProtection("test".toCharArray()));
    }

    private void testOrphanedCertCleanup()
        throws Exception
    {
        KeyPair kp1 = TestUtils.generateRSAKeyPair();
        KeyPair kp1ca = TestUtils.generateRSAKeyPair();
        KeyPair kp1ee = TestUtils.generateRSAKeyPair();

        X509Certificate kp1Root = TestUtils.generateRootCert(kp1, new X500Name("CN=KP1 ROOT"));
        X509Certificate kp1CA = TestUtils.generateIntermediateCert(kp1ca.getPublic(), new X500Name("CN=KP1 CA"), kp1.getPrivate(), kp1Root);
        X509Certificate kp1EE = TestUtils.generateEndEntityCert(kp1ee.getPublic(), new X500Name("CN=KP1 EE"), kp1ca.getPrivate(), kp1CA);

        Certificate[] kp1Chain = new Certificate[]{kp1EE, kp1CA, kp1Root};

        KeyPair kp2 = TestUtils.generateRSAKeyPair();
        KeyPair kp2ca = TestUtils.generateRSAKeyPair();
        KeyPair kp2ee = TestUtils.generateRSAKeyPair();

        X509Certificate kp2Root = TestUtils.generateRootCert(kp2, new X500Name("CN=KP2 ROOT"));
        X509Certificate kp2CA = TestUtils.generateIntermediateCert(kp2ca.getPublic(), new X500Name("CN=KP2 CA"), kp2.getPrivate(), kp1Root);
        X509Certificate kp2EE = TestUtils.generateEndEntityCert(kp2ee.getPublic(), new X500Name("CN=KP2 EE"), kp2ca.getPrivate(), kp1CA);

        Certificate[] kp2Chain = new Certificate[]{kp2EE, kp2CA, kp2Root};

        KeyPair kp3 = TestUtils.generateRSAKeyPair();
        X509Certificate kp3Root = TestUtils.generateRootCert(kp3, new X500Name("CN=KP3 ROOT"));

        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC);

        keyStore.load(null, null);

        keyStore.setKeyEntry("kp1", kp1ee.getPrivate(), null, kp1Chain);
        keyStore.setCertificateEntry("kp1root", kp1Root);
        keyStore.setKeyEntry("kp2", kp1ee.getPrivate(), null, kp2Chain);

        keyStore.setCertificateEntry("kp3root", kp3Root);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, "fred".toCharArray());

        byte[] baseData = bOut.toByteArray();

        KeyStore ks1 = KeyStore.getInstance("PKCS12", BC);

        ks1.load(new ByteArrayInputStream(baseData), "fred".toCharArray());

        if (!ks1.containsAlias("kp1") || !ks1.isKeyEntry("kp1") || ks1.getCertificateChain("kp1").length != 3)
        {
            fail("kp1 missing in ks1");
        }

        ks1.deleteEntry("kp1");

        ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();

        ks1.store(bOut1, "fred".toCharArray());

        KeyStore ks2 = KeyStore.getInstance("PKCS12", BC);

        ks2.load(new ByteArrayInputStream(bOut1.toByteArray()), "fred".toCharArray());

        if (!ks2.containsAlias("kp2") || !ks2.isKeyEntry("kp2") || ks2.getCertificateChain("kp2").length != 3)
        {
            fail("kp2 missing in ks2");
        }

        if (!ks2.containsAlias("kp1root") || !ks2.isCertificateEntry("kp1root"))
        {
            fail("kp1root missing in ks2");
        }

        if (!ks2.containsAlias("kp3root") || !ks2.isCertificateEntry("kp3root"))
        {
            fail("kp3root missing in ks2");
        }

        if (ks2.size() != 3)
        {
            fail("ks2 wrong size");
        }

        ks2.deleteEntry("kp2");

        ByteArrayOutputStream bOut2 = new ByteArrayOutputStream();

        ks2.store(bOut2, "fred".toCharArray());

        KeyStore ks3 = KeyStore.getInstance("PKCS12", BC);

        ks3.load(new ByteArrayInputStream(bOut2.toByteArray()), "fred".toCharArray());

        if (!ks3.containsAlias("kp1root") || !ks3.isCertificateEntry("kp1root"))
        {
            fail("kp1root missing in ks3");
        }

        if (!ks3.containsAlias("kp3root") || !ks3.isCertificateEntry("kp3root"))
        {
            fail("kp3root missing in ks3");
        }

        if (ks3.size() != 2)
        {
            fail("ks3 wrong size");
        }
    }

    private void testIterationCount()
        throws Exception
    {
        System.setProperty("org.bouncycastle.pkcs12.max_it_count", "10");

        ByteArrayInputStream stream = new ByteArrayInputStream(pkcs12StorageIssue);
        KeyStore store = KeyStore.getInstance("PKCS12", BC);

        try
        {
            store.load(stream, storagePassword);
            fail("no exception");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage().endsWith("iteration count 2000 greater than 10"));
        }

        System.clearProperty("org.bouncycastle.pkcs12.max_it_count");
    }

    private void testPBMac1PBKdf2()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("PKCS12", BC);
        final char[] password = "1234".toCharArray();
        ByteArrayInputStream stream;
        // valid test vectors
        for (byte[] test_vector : new byte[][]{pkcs12WithPBMac1PBKdf2_a1, pkcs12WithPBMac1PBKdf2_a2, pkcs12WithPBMac1PBKdf2_a3})
        {
            //
            // load test
            //
            stream = new ByteArrayInputStream(test_vector);
            store.load(stream, password);
            
            try
            {
                store.load(stream, "not right".toCharArray());
                fail("no exception");
            }
            catch (IOException ignored) {}

            //
            // save test
            //
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            store.store(bOut, passwd);
            stream = new ByteArrayInputStream(bOut.toByteArray());
            store.load(stream, passwd);

            //
            // save test using LoadStoreParameter
            //
            bOut = new ByteArrayOutputStream();
            PKCS12StoreParameter storeParam = new PKCS12StoreParameter(bOut, passwd, true);
            store.store(storeParam);
            byte[] data = bOut.toByteArray();
            stream = new ByteArrayInputStream(data);
            store.load(stream, passwd);
        }
        // invalid test vectors
        for (byte[] test_vector : new byte[][]{pkcs12WithPBMac1PBKdf2_a4, pkcs12WithPBMac1PBKdf2_a5})
        {
            stream = new ByteArrayInputStream(test_vector);
            try
            {
                store.load(stream, password);
                fail("no exception");
            }
            catch (IOException e)
            {
                isTrue(e.getMessage().contains("PKCS12 key store mac invalid - wrong password or corrupted file."));
            }
        }
        // invalid test vector that throws exception
        stream = new ByteArrayInputStream(pkcs12WithPBMac1PBKdf2_a6);
        try
        {
            store.load(stream, password);
            fail("no exception");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage().contains("Key length must be present when using PBMAC1."));
        }
    }

    private void testBCFKSLoad()
        throws Exception
    {
        KeyStore k = KeyStore.getInstance("BCFKS", BC);

        try
        {
            k.load(new ByteArrayInputStream(pkcs12), passwd);
        }
        catch (IOException e)
        {
            isTrue("malformed sequence".equals(e.getMessage()));
        }

        KeyPair kp1 = TestUtils.generateRSAKeyPair();
        KeyPair kp1ca = TestUtils.generateRSAKeyPair();
        KeyPair kp1ee = TestUtils.generateRSAKeyPair();

        X509Certificate kp1Root = TestUtils.generateRootCert(kp1, new X500Name("CN=KP1 ROOT"));
        X509Certificate kp1CA = TestUtils.generateIntermediateCert(kp1ca.getPublic(), new X500Name("CN=KP1 CA"), kp1.getPrivate(), kp1Root);
        X509Certificate kp1EE = TestUtils.generateEndEntityCert(kp1ee.getPublic(), new X500Name("CN=KP1 EE"), kp1ca.getPrivate(), kp1CA);

        Certificate[] kp1Chain = new Certificate[]{kp1EE, kp1CA, kp1Root};

        KeyPair kp2 = TestUtils.generateRSAKeyPair();
        KeyPair kp2ca = TestUtils.generateRSAKeyPair();
        KeyPair kp2ee = TestUtils.generateRSAKeyPair();

        X509Certificate kp2Root = TestUtils.generateRootCert(kp2, new X500Name("CN=KP2 ROOT"));
        X509Certificate kp2CA = TestUtils.generateIntermediateCert(kp2ca.getPublic(), new X500Name("CN=KP2 CA"), kp2.getPrivate(), kp1Root);
        X509Certificate kp2EE = TestUtils.generateEndEntityCert(kp2ee.getPublic(), new X500Name("CN=KP2 EE"), kp2ca.getPrivate(), kp1CA);

        Certificate[] kp2Chain = new Certificate[]{kp2EE, kp2CA, kp2Root};

        KeyPair kp3 = TestUtils.generateRSAKeyPair();
        X509Certificate kp3Root = TestUtils.generateRootCert(kp3, new X500Name("CN=KP3 ROOT"));

        KeyStore keyStore = KeyStore.getInstance("BCFKS", BC);

        keyStore.load(null, null);

        keyStore.setKeyEntry("kp1", kp1ee.getPrivate(), null, kp1Chain);
        keyStore.setCertificateEntry("kp1root", kp1Root);
        keyStore.setKeyEntry("kp2", kp1ee.getPrivate(), null, kp2Chain);

        keyStore.setCertificateEntry("kp3root", kp3Root);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, "fred".toCharArray());

        KeyStore k12 = KeyStore.getInstance("PKCS12", BC);

        try
        {
            k12.load(new ByteArrayInputStream(bOut.toByteArray()), "fred".toCharArray());
        }
        catch (IOException e)
        {
            isTrue("illegal object in getInstance: org.bouncycastle.asn1.DLSequence".equals(e.getMessage()));
        }
    }

    private void testLoadRepeatedLocalKeyID()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(new ByteArrayInputStream(repeatedLocalKeyIdPfx), "".toCharArray());

        isTrue(store.getCertificateChain("d4be139f9db456d225a8dcd2969479d960d2514a") == null);
        isTrue(store.getCertificateChain("45cbf1116fb3f38b2984b3c7224cae70a74f7789").length == 1);
    }

    private void checkNoDuplicateOracleTrustedCertAttribute()
        throws Exception
    {
        String keystoreType = "PKCS12";
        String certificateAlias = "myAlias";
        String keystorePassword = "myPassword";

        KeyPair kp1 = TestUtils.generateRSAKeyPair();
        KeyPair kp2 = TestUtils.generateRSAKeyPair();

        // generate certificate
        X509Certificate rootCertificate = TestUtils.generateRootCert(kp1, new X500Name("CN=KP1 ROOT"));
        X509Certificate originalCertificate = TestUtils.generateEndEntityCert(kp2.getPublic(), new X500Name("CN=KP3 EE"), KeyPurposeId.id_kp_capwapAC, KeyPurposeId.id_kp_capwapWTP, kp1.getPrivate(), rootCertificate);

        // store original certificate to a truststore
        KeyStore firstTrustStore = KeyStore.getInstance("PKCS12", "BC");
        firstTrustStore.load(null, new char[0]);
        firstTrustStore.setCertificateEntry(certificateAlias, originalCertificate);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        firstTrustStore.store(bOut, keystorePassword.toCharArray());

        // read certificate from the truststore
        KeyStore firstTrustStoreReadAgain = KeyStore.getInstance("PKCS12", "BC");
        firstTrustStoreReadAgain.load(new ByteArrayInputStream(bOut.toByteArray()), keystorePassword.toCharArray());
        Certificate certificateReadFromFirstTrustStore = firstTrustStoreReadAgain.getCertificate(certificateAlias);

        KeyStore secondTrustStore = KeyStore.getInstance("PKCS12", "BC");
        secondTrustStore.load(null, new char[0]);
        secondTrustStore.setCertificateEntry(certificateAlias, certificateReadFromFirstTrustStore);
        bOut = new ByteArrayOutputStream();
        secondTrustStore.store(bOut, keystorePassword.toCharArray());
        
        KeyStore secondTrustStoreReadWithoutBc = KeyStore.getInstance("PKCS12", "SunJSSE");
        secondTrustStoreReadWithoutBc.load(new ByteArrayInputStream(bOut.toByteArray()), keystorePassword.toCharArray());
    }

    public String getName()
    {
        return "PKCS12Store";
    }

    private void testJKS()
        throws Exception
    {
        if (System.getProperty("java.version").indexOf("1.5.") == 0)
        {
            return;
        }

        KeyStore ks = KeyStore.getInstance("PKCS12", BC);

        ks.load(new ByteArrayInputStream(JKS_Store), JKS_TEST_PWD);

        isTrue(ks.isCertificateEntry("cert0"));
    }

    private void testStoreType(String storeType, boolean isMacExpected)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        KeyPair kp = kpGen.generateKeyPair();
        X509Certificate cert = TestUtils.createSelfSignedCert(new X500Name("CN=PKCS12 Test"), "SHA256withECDSA", kp);

        KeyStore keyStore = KeyStore.getInstance(storeType, "BC");
        keyStore.load(null, null);

        keyStore.setKeyEntry("key", kp.getPrivate(), null, new Certificate[]{cert});

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, passwd);

        KeyStore inStore = KeyStore.getInstance("PKCS12", "BC");

        inStore.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

        Key k = inStore.getKey("key", null);

        Pfx pfx = Pfx.getInstance(bOut.toByteArray());

        if (isMacExpected)
        {
            isTrue(pfx.getMacData() != null);
        }
        else
        {
            isTrue(pfx.getMacData() == null);
        }

    }

    private void testAES256_AES128()
        throws Exception
    {
        testStoreType("PKCS12-AES256-AES128", true);
    }

    private void testAES256GCM_AES128_GCM()
        throws Exception
    {
        testStoreType("PKCS12-AES256-AES128-GCM", false);
    }

    public void performTest()
        throws Exception
    {
        testPKCS12StoreFriendlyName();
        testIterationCount();
        testPBMac1PBKdf2();
        testPKCS12Store();
        testGOSTStore();
        testChainCycle();
        testBCFKSLoad();
        testCertsOnly();
        testJKS();
        testLoadRepeatedLocalKeyID();
        testDilithiumStore();
        testFalconStore();
        testNTRUStore();
        testSphincsPlusStore();
        testRawKeyBagStore();
        testAES256_AES128();
        testAES256GCM_AES128_GCM();

        // converter tests

        KeyStore kS = KeyStore.getInstance("PKCS12", BC);

        byte[] data = PKCS12Util.convertToDefiniteLength(pkcs12);
        kS.load(new ByteArrayInputStream(data), passwd);     // check MAC

        ASN1Encodable obj = new ASN1StreamParser(data).readObject();
        if (!(obj instanceof DLSequenceParser))
        {
            fail("Failed DER conversion test.");
        }

        data = PKCS12Util.convertToDefiniteLength(pkcs12, passwd, BC);
        kS.load(new ByteArrayInputStream(data), passwd); //check MAC

        obj = new ASN1StreamParser(data).readObject();
        if (!(obj instanceof DLSequenceParser))
        {
            fail("Failed deep DER conversion test - outer.");
        }

        Pfx pfx = Pfx.getInstance(obj);

        obj = new ASN1StreamParser(ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets()).readObject();
        if (!(obj instanceof DLSequenceParser))
        {
            fail("Failed deep DER conversion test - inner.");
        }

        testOrphanedCertCleanup();
        checkNoDuplicateOracleTrustedCertAttribute();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PKCS12StoreTest());
    }
}
