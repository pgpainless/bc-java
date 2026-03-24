package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class PQCOpenPGPTest
        extends APITest
{
    @Override
    public String getName() {
        return "PQCOpenPGPTest";
    }

    private static final String MSG = "Testing\n";
    /**
     * V6 fingerprint of the Ed25519 primary key of {@link #v6_Ed25519_MlKem768_X25519_KEY}.
     */
    private static final String v6_Ed25519_MlKem768_X25519_PRIMARY_FP = "c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947";
    /**
     * V6 fingerprint of the ML-KEM-768+X25519 subkey of {@link #v6_Ed25519_MlKem768_X25519_KEY}.
     */
    private static final String v6_Ed25519_MlKem768_X25519_SUBKEY_FP = "dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d";
    /**
     * Transferable secret key consisting of:
     * <ul>
     *     <li>v6 Ed25519 private key packet</li>
     *     <li>v6 direct-key self-signature</li>
     *     <li>user-id packet</li>
     *     <li>v6 positive certification self-signature</li>
     *     <li>v6 ML-KEM-768+X25519 private subkey packet</li>
     *     <li>v6 subkey binding signature</li>
     * </ul>
     */
    private static final String v6_Ed25519_MlKem768_X25519_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGZ3SFgBsAAAAg3LSTXMTIYPje/3KOQ480cxsp1t0/1w2687B8uqUTCvwArfra\n" +
            "hBTuKijHaDe4/1ZcaYn7Z67De15iWPC/vGa3J4DCngYfGwgAAAA/BYJndIWAAwsJ\n" +
            "BwIVCAIWAAKbAwIeCSKhBseJ4X2dvcp7PIM6PAY/6wNT+ArZEf4nho+wZF34A+lH\n" +
            "BScJAgcCAAAAADQ7EIBsYsSttPe/Uf3gEmjU8NG0Ej59FY8N8de0aowAompVXg4Q\n" +
            "T9j1IsjmU28Ex/k1PTewAx5OoeQpQbJ4jjH+R/OZ730kkv+c+1mea5dpJdINzS5Q\n" +
            "UUMgdXNlciAoVGVzdCBLZXkpIDxwcWMtdGVzdC1rZXlAZXhhbXBsZS5jb20+wosG\n" +
            "ExsIAAAALAWCZ3SFgAIZASKhBseJ4X2dvcp7PIM6PAY/6wNT+ArZEf4nho+wZF34\n" +
            "A+lHAAAAAD4xEPlvPfA18bTluf3pkoZII9dcKltRjMIkbZqDg5el9xpB50br+7lg\n" +
            "CeQ4FOlsdrb9u7+twdm46fd6pR74naBnq6puYgsQnlLpTfnWqX6BB7sHx8RrBmd0\n" +
            "hYAjAAAEwCIVC0MM9yTsGbi+Vd+byq3jJwhXETaUBKV1yAI0Q7BfXkJC3YN0sGUL\n" +
            "B1LIvZBSlFEx/9op4ncn+0J9IKeKzuu449mu2UdNA/XK+5wl+sGGdTVNrJq3s7R/\n" +
            "BktVNWBMG0t+eYBtItQaxwYucsOntcO344uH1BA+ZHIALxsHN6KrZPCeqfF9ppTB\n" +
            "8UAlvVR0JATPtyyuxFw6MUex06GlYzirMXafH8jK5KqZJbjBKWwPo7bIsBBbLpqk\n" +
            "9yQxb7YYJ6VQMGkitrRwWNwQxTGDTee8/FyUMIYklGMewmG65RkKrBMKICsBX7lD\n" +
            "1cQ7fisEp7Y+WoOVqass6FuOWKJLIhyrg+A93oUsNBhGz/iEgJehP2g8AQPNMnO+\n" +
            "IicgIwQdV+YJRreWKvQosYMHxtopQRWKRXmmrGKPFYeozvoo6qR+JImvIDgy0gV/\n" +
            "eEun8iVoQbxuBXPIQXJOicOFPiWjXisG/0G3rOyRE9o0ivlxZPku2qKayfFtMwxb\n" +
            "NWg54ieV/uRfrjRRHOnL0SaxigY8N0FIwaTB4uMeyqphG+Ri7nSgnLVxaES9/tzN\n" +
            "iKlgsuAuC5k7E+XPAonGy9Ikm+oHJ9hg0XKNzvyNR/uwWhB2WFmFDRB3ldVE3/wh\n" +
            "LLe7yPmptIFWZ3J2LaaFqTyUhoNW6spRkUWeNMgo3MxRS3QgmBGXqou6/7RT2tdV\n" +
            "rWIY8WJO5SmMnZcrJ6oX3qKYgFiJJgCTuUegr/cNNJNLE/shyedkdxfG6jaQSzrL\n" +
            "xOWg0fBHtrd1snWWryCofwi7ray3HjNnKjNddfiChjWkLpu5H2dYM/CzdnmmOlk9\n" +
            "71vJgeZ6SrivUlwLTHDIkVqVr5F+iPXHU+Wd6hcUxrIH4eUXTJFIUYiamSqb35cg\n" +
            "AAzOBBS/DKwD46pOURchwRNRUbu47qiJE4AT6Ia0dTFkCSRezaJXBNe9+oisPDct\n" +
            "QTx/VZaktkvK4hc+DLwuMiQuQMoev0CgzLlr7XpxvCaEGYOiFTJydFtlhepmheZ3\n" +
            "k0puE5lY8AOJBEd1PKPEDzwqD0wOBxaMTEQGiPqH39ENs4q08BcOXjANqwtjxVot\n" +
            "JIurlBcxgsZ16RZOyiaRcCs358AMrExMScNfU+HBIONqxRkzCPOqn3sCMzQO+dwJ\n" +
            "uxNUoEYDcUAtYos8+1BdaHvGaeNMY3EuxQWeAJQEN4dpYfe29qlcYOwcHRtYosmL\n" +
            "c7OaHMQ7wnCzdJeyiHobAIgVZGZvAyW6w9cTlQd2pTdsDgSmO8or69gYPKxsmLei\n" +
            "b3JoytejtBhnaexyfeCFhksHzJlu48l65fDFE3h5Pmqj8vRGfFik2qbIzrU11ala\n" +
            "/IiJD7RnwTQCYuO++yKBa7rC1qXCXBFZixBwwTavHeEAPNnMmWxDfna2frNnFKRo\n" +
            "dDaTM7o76Gs7rgTIeLAzQfZih1yAJpSwjEcVDZdIRaRTrkK/4PJzVHGb4wwkOwfL\n" +
            "oPEBCMuAYTxfqJVEgdBi6pUsPaEOQzkUeIeOVgoFnMhP3+N22fMWkCBc/LYOThtP\n" +
            "XFWtHkq5jmmj+aiuyGOaadccBKWTvxloBly25QADfbYI2oImtVu1JDjFCf6PQ74U\n" +
            "WSEf9EvmTgsMQq/TPICLDUyoTkteLTQAwE2+uDYPxbo85xlZ2/yGneciXS8MvfqB\n" +
            "z8ZOI/y0C3xRsn7ZFZ2nEAaP9RUboQSSkc/gerixe47HC7X+MP6h7UAy49+ndvRO\n" +
            "6AHx2zZzPiDlZ0NgX3p6Aem45zjfMT7+wosGGBsIAAAALAWCZ3SFgAKbDCKhBseJ\n" +
            "4X2dvcp7PIM6PAY/6wNT+ArZEf4nho+wZF34A+lHAAAAAMitELFBvWMJM18SWIqP\n" +
            "kabwnOQbeR9GdZt2dJZF0YO8qGRmLO+T7GIaYj9TlzHonA3y01AAlYdfvolBM2gL\n" +
            "pujFf59V4t3iZxgQfgvs0+vrcSsE\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    /**
     * Corresponding transferable public key of {@link #v6_Ed25519_MlKem768_X25519_KEY}.
     * Consists of:
     * <ul>
     *     <li>v6 Ed25519 Public Key packet</li>
     *     <li>v6 direct-key self-signature</li>
     *     <li>user-id packet</li>
     *     <li>v6 positive certification self-signature</li>
     *     <li>v6 ML-KEM-768+X25519 public subkey packet</li>
     *     <li>v6 subkey binding signature</li>
     * </ul>
     */
    private static final String v6_Ed25519_MlKem768_X25519_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xioGZ3SFgBsAAAAg3LSTXMTIYPje/3KOQ480cxsp1t0/1w2687B8uqUTCvzCngYf\n" +
            "GwgAAAA/BYJndIWAAwsJBwIVCAIWAAKbAwIeCSKhBseJ4X2dvcp7PIM6PAY/6wNT\n" +
            "+ArZEf4nho+wZF34A+lHBScJAgcCAAAAADQ7EIBsYsSttPe/Uf3gEmjU8NG0Ej59\n" +
            "FY8N8de0aowAompVXg4QT9j1IsjmU28Ex/k1PTewAx5OoeQpQbJ4jjH+R/OZ730k\n" +
            "kv+c+1mea5dpJdINzS5QUUMgdXNlciAoVGVzdCBLZXkpIDxwcWMtdGVzdC1rZXlA\n" +
            "ZXhhbXBsZS5jb20+wosGExsIAAAALAWCZ3SFgAIZASKhBseJ4X2dvcp7PIM6PAY/\n" +
            "6wNT+ArZEf4nho+wZF34A+lHAAAAAD4xEPlvPfA18bTluf3pkoZII9dcKltRjMIk\n" +
            "bZqDg5el9xpB50br+7lgCeQ4FOlsdrb9u7+twdm46fd6pR74naBnq6puYgsQnlLp\n" +
            "TfnWqX6BB7sHzsQKBmd0hYAjAAAEwCIVC0MM9yTsGbi+Vd+byq3jJwhXETaUBKV1\n" +
            "yAI0Q7BfXkJC3YN0sGULB1LIvZBSlFEx/9op4ncn+0J9IKeKzuu449mu2UdNA/XK\n" +
            "+5wl+sGGdTVNrJq3s7R/BktVNWBMG0t+eYBtItQaxwYucsOntcO344uH1BA+ZHIA\n" +
            "LxsHN6KrZPCeqfF9ppTB8UAlvVR0JATPtyyuxFw6MUex06GlYzirMXafH8jK5KqZ\n" +
            "JbjBKWwPo7bIsBBbLpqk9yQxb7YYJ6VQMGkitrRwWNwQxTGDTee8/FyUMIYklGMe\n" +
            "wmG65RkKrBMKICsBX7lD1cQ7fisEp7Y+WoOVqass6FuOWKJLIhyrg+A93oUsNBhG\n" +
            "z/iEgJehP2g8AQPNMnO+IicgIwQdV+YJRreWKvQosYMHxtopQRWKRXmmrGKPFYeo\n" +
            "zvoo6qR+JImvIDgy0gV/eEun8iVoQbxuBXPIQXJOicOFPiWjXisG/0G3rOyRE9o0\n" +
            "ivlxZPku2qKayfFtMwxbNWg54ieV/uRfrjRRHOnL0SaxigY8N0FIwaTB4uMeyqph\n" +
            "G+Ri7nSgnLVxaES9/tzNiKlgsuAuC5k7E+XPAonGy9Ikm+oHJ9hg0XKNzvyNR/uw\n" +
            "WhB2WFmFDRB3ldVE3/whLLe7yPmptIFWZ3J2LaaFqTyUhoNW6spRkUWeNMgo3MxR\n" +
            "S3QgmBGXqou6/7RT2tdVrWIY8WJO5SmMnZcrJ6oX3qKYgFiJJgCTuUegr/cNNJNL\n" +
            "E/shyedkdxfG6jaQSzrLxOWg0fBHtrd1snWWryCofwi7ray3HjNnKjNddfiChjWk\n" +
            "Lpu5H2dYM/CzdnmmOlk971vJgeZ6SrivUlwLTHDIkVqVr5F+iPXHU+Wd6hcUxrIH\n" +
            "4eUXTJFIUYiamSqb35cgAAzOBBS/DKwD46pOURchwRNRUbu47qiJE4AT6Ia0dTFk\n" +
            "CSRezaJXBNe9+oisPDctQTx/VZaktkvK4hc+DLwuMiQuQMoev0CgzLlr7XpxvCaE\n" +
            "GYOiFTJydFtlhepmheZ3k0puE5lY8AOJBEd1PKPEDzwqD0wOBxaMTEQGiPqH39EN\n" +
            "s4q08BcOXjANqwtjxVotJIurlBcxgsZ16RZOyiaRcCs358AMrExMScNfU+HBIONq\n" +
            "xRkzCPOqn3sCMzQO+dwJuxNUoEYDcUAtYos8+1BdaHvGaeNMY3EuxQWeAJQEN4dp\n" +
            "Yfe29qlcYOwcHRtYosmLc7OaHMQ7wnCzdJeyiHobAIgVZGZvAyW6w9cTlQd2pTds\n" +
            "DgSmO8or69gYPKxsmLeib3JoytejtBhnaexyfeCFhksHzJlu48l65fDFE3h5Pmqj\n" +
            "8vRGfFik2qbIzrU11ala/IiJD7RnwTQCYuO++yKBa7rC1qXCXBFZixBwwTavHeEA\n" +
            "PNnMmWxDfna2frNnFKRodDaTM7o76Gs7rgTIeLAzQfZih1yAJpSwjEcVDZdIRaRT\n" +
            "rkK/4PJzVHGb4wwkOwfLoPEBCMuAYTxfqJVEgdBi6pUsPaEOQzkUeIeOVgoFnMhP\n" +
            "3+N22fMWkCBc/LYOThtPXFWtHkq5jmmj+aiuyGOaadccBKWTvxloBly25QADfbYI\n" +
            "2oImtVu1JDjFCf6PQ74UWSEf9EvmTgsMQq/TPICLDUyoTkteLTTCiwYYGwgAAAAs\n" +
            "BYJndIWAApsMIqEGx4nhfZ29yns8gzo8Bj/rA1P4CtkR/ieGj7BkXfgD6UcAAAAA\n" +
            "yK0QsUG9YwkzXxJYio+RpvCc5Bt5H0Z1m3Z0lkXRg7yoZGYs75PsYhpiP1OXMeic\n" +
            "DfLTUACVh1++iUEzaAum6MV/n1Xi3eJnGBB+C+zT6+txKwQ=\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    /**
     * Signed message "Testing\n" encrypted to {@link #v6_Ed25519_MlKem768_X25519_CERT} and signed
     * by {@link #v6_Ed25519_MlKem768_X25519_KEY}.
     * Consists of a v6 PKESK and a v2 SEIPD packet.
     * <p>
     * The hex-encoded mlkemKeyShare input to multiKeyCombine is <pre>
     *     b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797
     * </pre>
     * The hex-encoded ecdhKeyShare input to multiKeyCombine is <pre>
     *     9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932
     * </pre>
     * The hex-encoded output of multiKeyCombine is <pre>
     *     5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590
     * </pre>
     * The hex-encoded session key is <pre>
     *     94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435
     * </pre>
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-17.html#name-encrypted-and-signed-messag">
     *     draft-ietf-openpgp-pqc-17 - A.1.3 Encrypted and Signed Message</a>
     */
    private static final String v6_Ed25519_MlKem768_X25519_MSG = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcPtBiEG2v4O67JnXs/Nwgoj/onKXRLoP1J9+jVLbc9mITGki50jheL+TOBHsjFH\n" +
            "wVgycjiaAbS8K5lgfQw4rBjSqx16Smu90uphsP45SHdcYxgCXThuQ7TN+iSi+eCg\n" +
            "6NwID4cGRb4jVXdg0S9ur3ehWmC142K5BukkbWWBQDJM0hQa9DW+Lz+5PAb6JOfF\n" +
            "OGfbXzRTmuNBM8nePrigxOrtDe00K6qZlDvBjXOx5mvuCej/33WnfJFYPhxpZfv0\n" +
            "+605dm/Sy+I0QUpaKrViXZoR4Z01gm35NKgYCUmYPV9MspsF8ayZliOWkTnLbauU\n" +
            "WuDCTl8KNbMQ4WP5QOaxs65CV82AYMkpRBoCmsgjfFBy8fxSeqIKh1qghV3s+7xD\n" +
            "cpSxUc+22O//NMNTq6nwDeMwjQ8kOl5EhFWD0WT2QNXBPMTXrQV0jox5viI+ogom\n" +
            "O+SkE3I66B77OKtOwNP4CQ8dFD2hJpk/G1+ymGNyhMqYCN4hTa4aIl7LAB1Kpvjc\n" +
            "1ZSK4xijo2m4ua89V9eidgKio8RrikzEe6kwOydA21lnyHjCDPfZ3CYtDp0BYXgB\n" +
            "rl0MnZWCGMj/tMU4Pa6qvK7/m0szCpEYOy+nYEnfgiohsuf4lU2GeybUrFYOv51W\n" +
            "EF4X6nRatKz/Bz25Tzr1XYgYPbMyOm3gUPR0TH3llNur3EoQLq4n4br9ejUX/VfK\n" +
            "ZPEkWkug/Im8pnz82lv0aqJVqnyEeDY0ViIDbCnjVHhI9CVck8rstECjLcJSk9Tz\n" +
            "qS+8Tpi07ie6F91XARiaBwd8HopF4R1LmnKcEhEF7/7cJVKTaa0mZR5FRzIGn1oK\n" +
            "e0ANAN0LFP5w2HZqXbpmuRwKrpyfkIsHYjFRGO9xDMf7uPIqPzE1qL2yVIfpeDGp\n" +
            "rHvJbGzcTJ86r5qHA//257mArffHD24QWytBivPkFDJRWIIQh3Nu3tNwWif5kTar\n" +
            "Tgr66CPfwBa/hLeQWPGcFq0ylh3rhG8CYvxY5cyj4OSCp3Q7M3dxodS2XsWICKoU\n" +
            "GDo0E9uieJc7f80397DGp4E3BgP7s/Xk2ncWT7NlrpctYgFiMKCjEdSWbO08C8RG\n" +
            "8OYgBnMcY3p5xqk2u621JcCeus3uf3Kg6wUBPokja5XdlLbVQId+80MzEDyjhv3x\n" +
            "6c/F0az/Lrzq3/2dpn3vy0rU9WZ593WRnVZ70pcIWQqaJYCiOyZ7mkTkqyhg8P38\n" +
            "YUZuFtSGGk69n7QD3bdZBjbzMRnvevQuxXe6+WeXaT9uvEY/GKLestgpoI1aDS97\n" +
            "OfmxdOJafVJNjDzl2DJyKEpCdqCOsTabVfLaGu6C3NQTNjcHJNXJhTF8Bt9c6d1W\n" +
            "ISDESfmHtDnztMW+Y/y+juU/hFwK9wl3do1hOHQvqdUrskh+a7rZv4nUt9Badle6\n" +
            "oZtSzXmDM+5PVqU2LQ6RIrOeZ2SoIMBv4PnsykerAoUwRUH4z4gkQi0rU3r4wVta\n" +
            "6kDfo9HltNd5sl6Afy4SYE06+VsJ9fpr1Q4jKEHbNhankPgpvs0CQUMyUlA8HBn0\n" +
            "5eqmkIRGAihzdKJzUktiPgYAtg5sC+T1owxmLuzirbEzFQlUcgRLDzNG1UFeizdy\n" +
            "0sB5AgkCDEZm5g/ljKo0pPuGEZHCwXXAJTc4NlcTGZVms9el2uztFUgs2t+4e42t\n" +
            "811CsmDm2+2Dgs6TPzGkv4/9yNSKtoZWFE7OfotPsAtz0Lh4e3sDOAky3ZssjcHL\n" +
            "LdiKUVpTFGO7x+hQQewYMXLNushBVDHdxSYy1SYCRRh+K/yzgIkjZv+rtAIfL8tp\n" +
            "ZA4yVEMYXpsBNj4477QzhxlZrBhC3DQrjuqOGqKmewd5fsF87efpXwabHgdOwE0J\n" +
            "vqDodfstqnuEDGPpmGK8HsrEGBC/B4n5+VhHD7Ew5lOO0Js3xcux8DVjtNF8evet\n" +
            "AalNDVNZCxs+gntG0LZZ7dBYw20TDQ61cWVIKek9UHzFDeG5OzdffFcSm2kURDhv\n" +
            "ngqFrEkdOzaOHiIZarV74y3G3wZyzXobjp+dpA==\n" +
            "-----END PGP MESSAGE-----";

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        decryptAndVerify_v6_Ed25519_MlKem768_X25519_message(api);
    }

    public void decryptAndVerify_v6_Ed25519_MlKem768_X25519_message(OpenPGPApi api)
            throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(v6_Ed25519_MlKem768_X25519_KEY);
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(v6_Ed25519_MlKem768_X25519_CERT);

        ByteArrayInputStream bIn = new ByteArrayInputStream(v6_Ed25519_MlKem768_X25519_MSG.getBytes(StandardCharsets.UTF_8));
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(cert)
                .addDecryptionKey(key)
                .process(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        org.bouncycastle.util.io.Streams.pipeAll(mIn, bOut);
        mIn.close();
        OpenPGPMessageInputStream.Result result = mIn.getResult();
        isEncodingEqual(MSG.getBytes(StandardCharsets.UTF_8), bOut.toByteArray());
    }

    public static void main(String[] args)
    {
        runTest(new PQCOpenPGPTest());
    }
}
