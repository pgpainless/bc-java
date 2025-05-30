package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ElephantEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ElephantTest
    extends SimpleTest
{
    public String getName()
    {
        return "Elephant";
    }

    public void performTest()
        throws Exception
    {
        testVectors(ElephantEngine.ElephantParameters.elephant200, "v200");
        testVectors(ElephantEngine.ElephantParameters.elephant160, "v160");
        testVectors(ElephantEngine.ElephantParameters.elephant176, "v176");

        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 41, 10, 128, 12, new ElephantEngine(ElephantEngine.ElephantParameters.elephant160));
        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 41, 10, 128, 12, new ElephantEngine(ElephantEngine.ElephantParameters.elephant176));
        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 41, 10, 128, 12, new ElephantEngine(ElephantEngine.ElephantParameters.elephant200));
        CipherTest.checkAEADParemeter(this, 16, 12, 8, 20, new ElephantEngine(ElephantEngine.ElephantParameters.elephant160));
        CipherTest.checkAEADParemeter(this, 16, 12, 8, 22, new ElephantEngine(ElephantEngine.ElephantParameters.elephant176));
        CipherTest.checkAEADParemeter(this, 16, 12, 16, 25, new ElephantEngine(ElephantEngine.ElephantParameters.elephant200));
        CipherTest.testOverlapping(this, 16, 12, 8, 20, new ElephantEngine(ElephantEngine.ElephantParameters.elephant160));
        CipherTest.testOverlapping(this, 16, 12, 8, 22, new ElephantEngine(ElephantEngine.ElephantParameters.elephant176));
        CipherTest.testOverlapping(this, 16, 12, 16, 25, new ElephantEngine(ElephantEngine.ElephantParameters.elephant200));
        CipherTest.checkAEADCipherOutputSize(this, 16, 12, 20, 8, new ElephantEngine(ElephantEngine.ElephantParameters.elephant160));
        CipherTest.checkAEADCipherOutputSize(this, 16, 12, 22, 8, new ElephantEngine(ElephantEngine.ElephantParameters.elephant176));
        CipherTest.checkAEADCipherOutputSize(this, 16, 12, 25, 16, new ElephantEngine(ElephantEngine.ElephantParameters.elephant200));
//        //testVectors(ElephantEngine.ElephantParameters.elephant160, "v160_2");
        ElephantEngine elephant = new ElephantEngine(ElephantEngine.ElephantParameters.elephant200);
        testExceptions(elephant, elephant.getKeyBytesSize(), elephant.getIVBytesSize(), elephant.getBlockSize());
        implTestParametersEngine(elephant, 16, 12, 16);
        CipherTest.checkCipher(10, 12, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new ElephantEngine(ElephantEngine.ElephantParameters.elephant160);
            }
        });
        CipherTest.checkCipher(10, 12, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new ElephantEngine(ElephantEngine.ElephantParameters.elephant176);
            }
        });
        CipherTest.checkCipher(10, 12, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new ElephantEngine(ElephantEngine.ElephantParameters.elephant200);
            }
        });



        elephant = new ElephantEngine(ElephantEngine.ElephantParameters.elephant160);
        testExceptions(elephant, elephant.getKeyBytesSize(), elephant.getIVBytesSize(), elephant.getBlockSize());
        implTestParametersEngine(elephant, 16, 12, 8);
        elephant = new ElephantEngine(ElephantEngine.ElephantParameters.elephant176);
        testExceptions(elephant, elephant.getKeyBytesSize(), elephant.getIVBytesSize(), elephant.getBlockSize());
        implTestParametersEngine(elephant, 16, 12, 8);

    }


    private void testVectors(ElephantEngine.ElephantParameters pbp, String filename)
        throws Exception
    {
        ElephantEngine Elephant = new ElephantEngine(pbp);
        CipherParameters params;
        InputStream src = TestResourceFinder.findTestResource("crypto/elephant",
            filename + "_LWC_AEAD_KAT_128_96.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] rv;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("689"))
//                {
//                    continue;
//                }
                byte[] key = Hex.decode(map.get("Key"));
                byte[] nonce = Hex.decode(map.get("Nonce"));
                byte[] ad = Hex.decode(map.get("AD"));
                byte[] pt = Hex.decode(map.get("PT"));
                byte[] ct = Hex.decode(map.get("CT"));
                params = new ParametersWithIV(new KeyParameter(key), nonce);
                Elephant.init(true, params);
                Elephant.processAADBytes(ad, 0, ad.length);
                rv = new byte[Elephant.getOutputSize(pt.length)];
                int len = Elephant.processBytes(pt, 0, pt.length, rv, 0);
                Elephant.doFinal(rv, len);
                if (!areEqual(rv, ct))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                Elephant.reset();
                Elephant.init(false, params);
                //Decrypt
                Elephant.processAADBytes(ad, 0, ad.length);
                rv = new byte[pt.length];
                len = Elephant.processBytes(ct, 0, ct.length, rv, 0);
                Elephant.doFinal(rv, len);
                byte[] pt_recovered = new byte[pt.length];
                System.arraycopy(rv, 0, pt_recovered, 0, pt.length);
                if (!areEqual(pt, pt_recovered))
                {
                    mismatch("Reccover Keystream " + map.get("Count"), (String)map.get("PT"), pt_recovered);
                }
                //System.out.println("Keystream " + map.get("Count") + " pass");
                Elephant.reset();
                map.clear();

            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        // System.out.println("Elephant AEAD pass");
    }

    private void testExceptions(AEADCipher aeadBlockCipher, int keysize, int ivsize, int blocksize)
        throws Exception
    {
        CipherParameters params;
        byte[] k = new byte[keysize];
        byte[] iv = new byte[ivsize];
        byte[] m = new byte[0];
        byte[] c1 = new byte[blocksize];
        params = new ParametersWithIV(new KeyParameter(k), iv);
//        try
//        {
//            aeadBlockCipher.processBytes(m, 0, m.length, c1, 0);
//            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before processBytes");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }

//        try
//        {
//            aeadBlockCipher.processByte((byte)0, c1, 0);
//            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before processByte");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }

//        try
//        {
//            aeadBlockCipher.reset();
//            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before reset");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }

        try
        {
            aeadBlockCipher.doFinal(c1, m.length);
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before dofinal");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.getMac();
            aeadBlockCipher.getAlgorithmName();
//            aeadBlockCipher.getOutputSize(0);
//            aeadBlockCipher.getUpdateOutputSize(0);
        }
        catch (IllegalStateException e)
        {
            //expected
            fail(aeadBlockCipher.getAlgorithmName() + " functions can be called before initialisation");
        }
        Random rand = new Random();
        int randomNum;
        while ((randomNum = rand.nextInt(100)) == keysize) ;
        byte[] k1 = new byte[randomNum];
        while ((randomNum = rand.nextInt(100)) == ivsize) ;
        byte[] iv1 = new byte[randomNum];
        try
        {
            aeadBlockCipher.init(true, new ParametersWithIV(new KeyParameter(k1), iv));
            fail(aeadBlockCipher.getAlgorithmName() + " k size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.init(true, new ParametersWithIV(new KeyParameter(k), iv1));
            fail(aeadBlockCipher.getAlgorithmName() + "iv size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        aeadBlockCipher.init(true, params);
        c1 = new byte[aeadBlockCipher.getOutputSize(0)];
        try
        {
            aeadBlockCipher.doFinal(c1, m.length);
        }
        catch (Exception e)
        {
            fail(aeadBlockCipher.getAlgorithmName() + " allows no input for AAD and plaintext");
        }
        byte[] mac2 = aeadBlockCipher.getMac();
        if (mac2 == null)
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should not be empty after dofinal");
        }
        if (!areEqual(mac2, c1))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should be equal when calling dofinal and getMac");
        }

//        aeadBlockCipher.reset();
//        aeadBlockCipher.processAADByte((byte)0);
//        byte[] mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
//        aeadBlockCipher.doFinal(mac1, 0);
//        if (areEqual(mac1, mac2))
//        {
//            fail(aeadBlockCipher.getAlgorithmName() + ": mac should not match");
//        }
//        aeadBlockCipher.reset();
//        aeadBlockCipher.processBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], 0);
//        try
//        {
//            aeadBlockCipher.processAADByte((byte)0);
//            fail(aeadBlockCipher.getAlgorithmName() + ": processAADByte(s) cannot be called after encryption/decryption");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }
//        try
//        {
//            aeadBlockCipher.processAADBytes(new byte[]{0}, 0, 1);
//            fail(aeadBlockCipher.getAlgorithmName() + ": processAADByte(s) cannot be called once only");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }

        aeadBlockCipher.reset();
        try
        {
            aeadBlockCipher.processAADBytes(new byte[]{0}, 1, 1);
            fail(aeadBlockCipher.getAlgorithmName() + ": input for processAADBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.processBytes(new byte[]{0}, 1, 1, c1, 0);
            fail(aeadBlockCipher.getAlgorithmName() + ": input for processBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
//        try
//        {
//            aeadBlockCipher.processBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], blocksize >> 1);
//            fail(aeadBlockCipher.getAlgorithmName() + ": output for processBytes is too short");
//        }
//        catch (OutputLengthException e)
//        {
//            //expected
//        }
        try
        {
            aeadBlockCipher.init(true, params);
            aeadBlockCipher.doFinal(new byte[2], 2);
            fail(aeadBlockCipher.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        byte[] mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
        mac2 = new byte[aeadBlockCipher.getOutputSize(0)];
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(new byte[]{0, 0}, 0, 2);
        aeadBlockCipher.doFinal(mac1, 0);
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADByte((byte)0);
        aeadBlockCipher.processAADByte((byte)0);
        aeadBlockCipher.doFinal(mac2, 0);
        if (!areEqual(mac1, mac2))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should match for the same AAD with different ways of inputing");
        }

        byte[] aad2 = {0, 1, 2, 3, 4};
        byte[] aad3 = {0, 0, 1, 2, 3, 4, 5};
        byte[] m2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] m3 = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] m4 = new byte[m2.length];
        aeadBlockCipher.init(true, params);
        byte[] c2 = new byte[aeadBlockCipher.getOutputSize(10)];
        byte[] c3 = new byte[aeadBlockCipher.getOutputSize(10) + 2];
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        int offset = aeadBlockCipher.processBytes(m2, 0, m2.length, c2, 0);
        aeadBlockCipher.doFinal(c2, offset);
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(aad3, 1, aad2.length);
        offset = aeadBlockCipher.processBytes(m3, 1, m2.length, c3, 1);
        aeadBlockCipher.doFinal(c3, offset + 1);
        byte[] c3_partial = new byte[c2.length];
        System.arraycopy(c3, 1, c3_partial, 0, c2.length);
        if (!areEqual(c2, c3_partial))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should match for the same AAD and message with different offset for both input and output");
        }
        aeadBlockCipher.reset();
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        aeadBlockCipher.doFinal(m4, offset);
        if (!areEqual(m2, m4))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": The encryption and decryption does not recover the plaintext");
        }

        c2[c2.length - 1] ^= 1;
        aeadBlockCipher.reset();
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            aeadBlockCipher.doFinal(m4, offset);
            fail(aeadBlockCipher.getAlgorithmName() + ": The decryption should fail");
        }
        catch (InvalidCipherTextException e)
        {
            //expected;
        }

        byte[] m7 = new byte[blocksize * 3];
        for (int i = 0; i < m7.length; ++i)
        {
            m7[i] = (byte)rand.nextInt();
        }
        aeadBlockCipher.init(true, params);
        byte[] c7 = new byte[aeadBlockCipher.getOutputSize(m7.length)];
        byte[] c8 = new byte[c7.length];
        byte[] c9 = new byte[c7.length];

        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, m7.length, c7, 0);
        aeadBlockCipher.doFinal(c7, offset);
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, blocksize, c8, 0);
        offset += aeadBlockCipher.processBytes(m7, blocksize, m7.length - blocksize, c8, offset);
        aeadBlockCipher.doFinal(c8, offset);

        // random split for several times
        for (int split = 0; split < blocksize * 3; ++split)
        {
            aeadBlockCipher.init(true, params);
            aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
            offset = aeadBlockCipher.processBytes(m7, 0, split, c9, 0);
            offset += aeadBlockCipher.processBytes(m7, split, m7.length - split, c9, offset);
            aeadBlockCipher.doFinal(c9, offset);
            if (!areEqual(c7, c8) || !areEqual(c7, c9))
            {
                fail(aeadBlockCipher.getAlgorithmName() + ": Splitting input of plaintext should output the same ciphertext");
            }
        }

        // System.out.println(aeadBlockCipher.getAlgorithmName() + " test Exceptions pass");
    }

    private void implTestParametersEngine(ElephantEngine cipher, int keySize, int ivSize,
                                          int macSize)
    {
        if (cipher.getKeyBytesSize() != keySize)
        {
            fail("key bytes of " + cipher.getAlgorithmName() + " is not correct");
        }
        if (cipher.getIVBytesSize() != ivSize)
        {
            fail("iv bytes of " + cipher.getAlgorithmName() + " is not correct");
        }

        CipherParameters parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

        cipher.init(true, parameters);
        if (cipher.getOutputSize(0) != macSize)
        {
            fail("getOutputSize of " + cipher.getAlgorithmName() + " is incorrect for encryption");
        }

        cipher.init(false, parameters);
        if (cipher.getOutputSize(macSize) != 0)
        {
            fail("getOutputSize of " + cipher.getAlgorithmName() + " is incorrect for decryption");
        }
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new ElephantTest());
    }
}

