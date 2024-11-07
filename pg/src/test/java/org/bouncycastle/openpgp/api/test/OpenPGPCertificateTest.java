package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class OpenPGPCertificateTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "OpenPGPCertificateTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        //baseCertificateTest();
        advanced();
    }

    private void baseCertificateTest()
            throws IOException
    {
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat
        String KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
                "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
                "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
                "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
                "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
                "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
                "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
                "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
                "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) objFac.nextObject();

        OpenPGPCertificate certificate = new OpenPGPCertificate(publicKeys, new BcPGPContentVerifierBuilderProvider());
        for (OpenPGPCertificate.OpenPGPCertificateComponent component : certificate.getComponents())
        {
            System.out.println(component + " is bound at " + certificate.getEvaluationTime() + ": " + certificate.isAuthenticated(component));
            System.out.println(certificate.getAllSignatureChainsFor(component));
        }
    }

    private void advanced() throws IOException {
        String KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwM8EIAEKAIMFglwqrYAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z1X0jZPeNNpSsn78ulDPJNHa0QaeI5oAUdBGbIKSOT0uEx0BS2V5IGlzIHN1cGVy\n" +
                "c2VkZWQWIQTjLLbaggKRt+dtsagIrVHK5HDwBgAAr2QIAKAY5bHFbRkoItYBJBN1\n" +
                "aV1jjrpYdwLM+0LHf8GcRCeO1Pt9I1J021crwTw14sTCxi6WH4qbQSBxRqAEej/A\n" +
                "wfk1kmkm4WF7zTUT+fXIHDJxFJJXqFZ+LWldYYEVqSi02gpbYkyLm9hxoLDoAxS2\n" +
                "bj/sFaH4Bxr/eUCqjOiEsGzdY1m65+cp5jv8cJK05jwqxO5/3KZcF/ShA7AN3dJi\n" +
                "NAokoextBtXBWlGvrDIfFafOy/uCnsO6NeORWbgZ88TOXPD816ff5Y8kMwkDkIk2\n" +
                "9dK4m0aL/MDI+Fgx78zRYwn5xHbTMaFz+hex+gjo4grx3KYXeoxBAchUuTsVNoo4\n" +
                "kbfCwMQEHwEKAHgFgl4L4QAJEAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRp\n" +
                "b25zLnNlcXVvaWEtcGdwLm9yZ4csZe1ah1tj2AjxfdDMsH2wvSEwZjb/73ICKnm7\n" +
                "BySQAhUKApsDAh4BFiEE4yy22oICkbfnbbGoCK1RyuRw8AYAAGYFCACiKnCb2NBZ\n" +
                "a/Jj1aJe4R2rxPZj2ERXWe3bJKNPKT7K0rVDkTw1JRiTfCsuAY2lY9sKJdhQZl+a\n" +
                "zXm64vvTc6hEGRQ/+XssDlE2DIn8C34HDc495ZnryHNB8Dd5l1HdjqxfGIY6HBPJ\n" +
                "Udx0dedwP42Oisg9t5KsC8zld/+MIRgzkp+Dg0LXJVnDuwWEPoo2N6WhAr5ReLvX\n" +
                "xALX5ht9Lb3lP0DASZvAKy9BO/wRCr294J8dg/CowAfloyf0Ko+JjyjanmZn3acy\n" +
                "5CGkVN2mc+PFUekGZDDy5ooYkgXO/CmApuTNvabct+A7IVVdWWM5SWb90JvaV9SW\n" +
                "ji6nQphVm7StwsDEBB8BCgB4BYJaSXoACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0\n" +
                "QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfVZdjLYZxDX2hvy3aGrsE4i0avLDMz\n" +
                "f3e9kVHmaD6PAgIVCgKbAwIeARYhBOMsttqCApG3522xqAitUcrkcPAGAABQYwgA\n" +
                "rfIRxq95npUKAOPXs25nZlvy+xQbrmsTxHhAYW8eGFcz82QwumoqrR8VfrojxM+e\n" +
                "CZdTI85nM5kzznYDU2+cMhsZVm5+VhGZy3e3QH4J/E31D7t1opCvj5g1eRJ4Lgyw\n" +
                "B+cYGcZBYp/bQT9SUYuhZH2OXCR04qSbpVUCIApnhBHxKNtOlqjAkHeaOdW/8XeP\n" +
                "sbfvrtVOLGYgrZXfY7Nqy3+Wzbdm8UvVPFXH+uHEzTgyvYbnJBYkjORmCqUKs860\n" +
                "PL8ekeg+sL4PHSRj1UUfwcQD55q0m3Vtew2KiIUi4wKi5LceDtprjoO5utU/1YfE\n" +
                "AiNMeSQHXKq83dpazvjrUs0SanVsaWV0QGV4YW1wbGUub3JnwsDEBBMBCgB4BYJa\n" +
                "SXoACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn\n" +
                "cC5vcmc6Rix7CeIfWwnaQjk3bBrkAiY7jS9N+shuRdHZ0gKKsgIVCgKbAwIeARYh\n" +
                "BOMsttqCApG3522xqAitUcrkcPAGAACf9QgAsxtfAbyGbtofjrXTs9lsKEWvGgk0\n" +
                "2fSYyKjPbyaRqh72MlIlUXwqq1ih2TJc3vwF8aNVDrcb9DnBabdt2M1vI3PUaeG3\n" +
                "1BmakC/XZCNCrbbJkyd/vdMLqw7prLrp0auVNNhLYxOK9usXbClNxluo4i/lSFVo\n" +
                "5B9ai+ne1kKKiplzqy2qqhdeplomcwGHbB1CkZ04DmCMbSSFAGxYqUC/bBm0bolC\n" +
                "ebw/KIz9sEojNKt6mvsFN67/hMYeJS0HVlwwc6i8iKSzC2D53iywhtvkdiKECXQe\n" +
                "XDf9zNXAn1wpK01SLJ0iig7cDFrtoqkfPYzbNfC0bt34fNx9iz3w9aEH8c7ATQRa\n" +
                "SsuAAQgAu5yau9psltmWiUn7fsRSqbQInO0iWnu4DK9IXB3ghNYMcii3JJEjHzgI\n" +
                "xGf3GiJEjzubyRQaX5J/p7yB1fOH8z7FYUuax1saGf9c1/b02N9gyXNlHam31hNa\n" +
                "aL3ffFczI95p7MNrTtroTt5oZqsc+i+oKLZn7X0YAI4tEYwhSnUQYB/F7YqkkI4e\n" +
                "V+7CxZPA8pBhXiAOK/zn416PsZ6JS5wsM65yCtOHcAAIBnKDnC+bQi+f1WZesSoc\n" +
                "y/rXx3QEQmodDu3ojhS+VxcYGeZCUcFF0FyZBIkGjHIVQLyOfjP3FRJ4qFXMz9/Y\n" +
                "IVoM4Y6guTERMTEj/KDG4BP7RfJHTQARAQABwsI8BBgBCgHwBYJeC+EACRAIrVHK\n" +
                "5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfcAa1Z\n" +
                "PWTtg60w3Oo4dt4Fa8cKFYbZYsqDSHV5pwEfMwKbAsC8oAQZAQoAbwWCXgvhAAkQ\n" +
                "EPy8/w6Op5FHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn\n" +
                "L6I2+VyN5T1FoVgj3cdnMLYCpcB5i/FRSCVKybuLzrgWIQTOphDQhPpR8hHhxGwQ\n" +
                "/Lz/Do6nkQAArk8H/AhjM9lqbffFL6RRR4HTjelspy4A3nyTicCljrDuXDUh23Gf\n" +
                "LvajTR5h16ZBqAF7cpb9rrlz1C1WcS5JLVxzXAe7f+KOfXu+eyLhpTzZ8VT3pK3h\n" +
                "HGaYwlVlXrBZP0JXgL8hm6hDSXZQZtcpsnQ1uIHC9ONxUB4liNFhTqQCQYdQJFiF\n" +
                "s1umUbo/C4KdzlDI08bM3CqEKat9vUFuGG68mDg0CrRZEWt946L5i8kZmBUkSShI\n" +
                "m2k5e2qE/muYeM6qKQNsxlx3VIf5eUhtxCi9fg7SjvHkdUSFstYcxAdaohWCFCEs\n" +
                "DJI12hzcKQazSjvtKF4BNBKgX/wLsbVQnYLd9ggWIQTjLLbaggKRt+dtsagIrVHK\n" +
                "5HDwBgAANjMH/1MY7DJyxkiTjc/jzmnVxqtHOZDCSmUqk0eh/6BHs+ostWqkGC6+\n" +
                "7dfxDnptwcqandYey4KF2ajt4nOwu0xQw/NEF3i81h7IiewY7G+YT69DUd+DvVUQ\n" +
                "emfKNYVOrMqoH7QU5o4YojdJiDeIp2d/JyJrqyof78JFAHnNZgHC2T2zo9E54dnO\n" +
                "TY9VNUNCOUct5Rby0GXjTIURO0f485eGuZxVWdLRllDYOiCrQHPSHhrxHVXVMbYJ\n" +
                "oroPy+IyaJanVoAWgyipBmmIDV8aINM2RLMsGkuPTRtITI2ZlGOQN7xgy4LqWzjP\n" +
                "nrzMXfwBEDx/nrwdG6zEGMK8AkVkMT5uJJvCwjwEGAEKAfAFglro/4AJEAitUcrk\n" +
                "cPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/Q0Z6WD\n" +
                "H2+8/F1xEEuiApsjnn2lGNZ2DeIaklJzdqQOApsCwLygBBkBCgBvBYJa6P+ACRAQ\n" +
                "/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfr\n" +
                "VATyX3tgcM2z41fqYquxVhJRavN6+w2SU4xEG++SqBYhBM6mENCE+lHyEeHEbBD8\n" +
                "vP8OjqeRAABGVggAsB8M2KI5cxXKKgVHL1dEfzg9halVavktfcT6ZVC/+aDp94tv\n" +
                "BCL16Guhq4ccN7DATrWx430/GecY6E77qvhDzmCclSbdLbiZmsrVX9kCmTfrJzFQ\n" +
                "64KfvIS5GgbL21+ZJ+pKW2HOMBGn6sgAPmTqM5UsDCpsEKDt5CJcJr3sTc8D9NhE\n" +
                "nc0dKsQ91+n9ms3W5tyyE6r9pyM6ThBCMhbQkR7hE9XWAQeO1ILSFGnie0aFcTU0\n" +
                "Oo0wL1MaiSyA/8XpKq23xfx1kNS9hQkdq0aWehNoTJdCt1Nq1cWABy2rQR0x+qhG\n" +
                "WowfsAjnBautxvet28t2kPCAIMniYpWc89BwfhYhBOMsttqCApG3522xqAitUcrk\n" +
                "cPAGAACq1gf/Q7H9Re5SWk+UOn/NQPRedf544YJ/YdQnve/hSaPGL33cUzf4yxzF\n" +
                "ILnK19Ird5f8/mTT1pg99L3ixE3N5031JJKwFpCB69Rsysg88ZLDL2VLc3xdsAQd\n" +
                "UbVaCqeRHKwtMtpBvbAFvF9plwam0SSXHHr/JkYm5ufXN6I8ib/nwr1bFbf/Se0W\n" +
                "uk9RG4ne9JUBCrGxakyVd+OgLLhvzOmJa7fDC0uUZhTKFbjMxLhaas4HFYiRbfz2\n" +
                "T0xz9gyDytDWsEFM+XoKHlEH8Fx/U2B5/8N0Q+pIFoEuOmBO+5EPvPIlxNByHgia\n" +
                "NIuKt1Mu+UAb2Spl6D5zbDfX/3vqxdhYHw==\n" +
                "=9epL\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        String T0 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJYaEaACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmdVa4OG6WfRoRlj5+Zb6avhJUIZFvcIFiLuvrJp8Hio\n" +
                "iBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAAAbaQgAjhBh0dLO0Sqiqkb2M3KWc25V\n" +
                "hJlcP3isFROJ0jikmXxkG9W04AvlA78tSxEP2n8a0CbxH/hT4g8mFb/qM5FKZcKf\n" +
                "HQxjbjUxBmVHa3EfMkwT7u1mVRmoWtJ59oVsKoqRb/kZ14i6VZ9NzfK8MRlL0e24\n" +
                "oNjkksZQ8ImjwwtvxSinxhezA6BtWi+dDnXAnG5Vva+6N/GRNPAAd8kFTPrlEqEz\n" +
                "uRbpq76r4taPjRjzMNcwZJoRVHSahWhDcXxNTalVUwt0DZFAskZ3gI+0VgU11bK1\n" +
                "QmIw2iR4itQY5f10HFNcl7uHLKnul0YyuvA5509HwCuEpdYUV/OxtlpVRaJ+yg==\n" +
                "=Rc6K\n" +
                "-----END PGP SIGNATURE-----\n";
        String T1 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfcG7Iqn3OOKVjeJ61MlgERt08kcxh0x+BZFD7a8K7V\n" +
                "VBYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAACBIwf9EoS24IFeT3cPFf/nWxLFkbZK\n" +
                "fiy9WzyK4wlpO3VTyWPbXi6zpC4I5Rbp2jDk/c7Q3DnOZqFDv6TriTwuLYTJGPxr\n" +
                "U3dtDsFcKp4FcbgFyCDKIuLB+3kLaNpMXqdttEkY3Wd5m33XrBB7M0l5xZCk56Jm\n" +
                "H5L1sGNNNkCzG6P44qu69o5fkWxbYuX22fyhdeyxucJHMztqiMQYDwT7eSA92A1v\n" +
                "5OwA5D/k7GeyYFBFisxRijkdVtxstC9zkagC19VnZo7MRekA9gXj7kIna4XYRhfb\n" +
                "uQnN47HXdiWQytwypLvZ8JEJpRruyMAaHjX5OBXh0SK11xYWb6wB93+QfOahtg==\n" +
                "=UlUZ\n" +
                "-----END PGP SIGNATURE-----\n";
        String T2 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJdP4iACRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcgkZw3ZSg8CZCKqJw2r4VqCpTuUhz6N0zX43d+1xop\n" +
                "2hYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAADnqAgAq+m6dDZpNOBaXH9nwv8/+HgR\n" +
                "MvRjnuLoa6zB5tcUhGPPVS0gg1PW0wfxlo1GPmgW3QDlV1zvcfYAZmV9uEC61wn/\n" +
                "+FkqN0Tceo487UvkWARE/mmRj5L8OgUTfqm1eebFQlMu/MeG9YOg+tXBy7XS7hy3\n" +
                "UdntIbtsv5oRTcybTnn5oiU2OFDlFC6sBNzOQt7wpyB1TKp2BdcsAv1RwmyCCCK4\n" +
                "bnmrpYH6woWMyVEVeMYfOHAx9vHD+od8Vf/v5L1M2N0nHzRWjjkobTVUr+xt/CyW\n" +
                "nq8SoazKYu3ETpZLeWX6Bciuv9+pzUCeClOSmBB1MFyyrTgbkOacHgrYnLvvtQ==\n" +
                "=WCKA\n" +
                "-----END PGP SIGNATURE-----\n";
        String T3 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJmhTYiCRAQ/Lz/Do6nkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmdi3dCpJ4nZincNH5owv8+fJ5YpXljqtegtoBEnbbHP\n" +
                "thYhBM6mENCE+lHyEeHEbBD8vP8OjqeRAAD0cQf/e8RHocRESJPbosqUuvC3ELnD\n" +
                "oSsJomDMUDfSfgpS5EhkOyJhvcrHkCbsHH2xlUEQ+zjJWY/dwM3FUkoj+p3kb/JC\n" +
                "Rn5cqQYlME+uJzjdHMyQCSOI1SvYwKCLCGPARDbCpeINrV++Oy29e6cv6/IcPlgo\n" +
                "k/0A7XuNq0YNxC7oopCj5ye3yVUvUmSCG2iV4oiWW5GhhPRzMeW7MFQmS0NUkAI8\n" +
                "hzJ8juTG4xP8SXnHCMakasZhJmtpMDd2BDZ7CrhWiWUQGrtd0eYkuyodreqVMGIF\n" +
                "BN80YgTNFW2MrblhDRRmxAqWzD9FedBwwSdgYbtkDwjsSq0S1jQV6aPndJqiLw==\n" +
                "=CIl0\n" +
                "-----END PGP SIGNATURE-----\n";
        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) objFac.nextObject();

        OpenPGPCertificate certificate = new OpenPGPCertificate(publicKeys, new BcPGPContentVerifierBuilderProvider());
        for (OpenPGPCertificate.OpenPGPCertificateComponent component : certificate.getComponents())
        {
            System.out.println(component + " is bound at " + certificate.getEvaluationTime() + ": " + certificate.isAuthenticated(component));
            System.out.println(certificate.getAllSignatureChainsFor(component));
        }

        for (String t : Arrays.asList(T0, T1, T2, T3))
        {
            bIn = new ByteArrayInputStream(t.getBytes(StandardCharsets.UTF_8));
            aIn = new ArmoredInputStream(bIn);
            pIn = new BCPGInputStream(aIn);
            objFac = new BcPGPObjectFactory(pIn);
            PGPSignatureList sigs = (PGPSignatureList) objFac.nextObject();
            PGPSignature sig = sigs.get(0);

            certificate.setEvaluationDateFor(sig);
            OpenPGPCertificate.OpenPGPSubkey subkey = certificate.getSubkeys()
                    .get(sig.getKeyIdentifiers().get(0));

            System.out.println(subkey + " is bound at " + certificate.getEvaluationTime() + ": " +
                    certificate.isAuthenticated(subkey));
        }
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPCertificateTest());
    }
}
