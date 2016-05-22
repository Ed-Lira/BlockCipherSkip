package net.eduardolira.blockcipherskip;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ShortBufferException {
        System.out.println("Without proper skipping:");
        System.out.println(demonstrate(false));
        System.out.println("Using BlockCipherSkipper");
        System.out.println(demonstrate(true));
    }

    /**
     * Demo method to show an example case for the BlockCipherSkipper
     * Without the {@link BlockCipherSkipper#drainBytes(InputStream, long)} method, the "World!" in "Hello World!"
     * returns garbage bytes since decryption is unsuccessful. For this example a AES key is being used to create Ciphers
     * operating in CBF8/NoPadding mode.
     *
     *sample output:
     *<p>
     *   Without proper CFB skipping:
     *   Hello t��~�
     *   Using CFBSkipper
     *   Hello World!
     *</p>
     *
     * @param useBlockCipherSkipper
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws ShortBufferException
     */
    public static String demonstrate(boolean useBlockCipherSkipper) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IOException, ShortBufferException {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey key = gen.generateKey();
        Cipher decryptionCipher = cipherFromSharedSecret(Cipher.DECRYPT_MODE, key);
        Cipher encryptionCipher = cipherFromSharedSecret(Cipher.ENCRYPT_MODE, key);
        BlockCipherSkipper skipper = new BlockCipherSkipper(decryptionCipher);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CipherOutputStream cos = new CipherOutputStream(baos,encryptionCipher);
        cos.write("Hello".getBytes(StandardCharsets.UTF_8));
        int garbageByteCount = 2258;
        for (int i = 0; i < garbageByteCount; i++) {
            cos.write(0);
        }
        cos.write("World!".getBytes(StandardCharsets.UTF_8));
        byte[] bytes = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

        byte[] helloBytes = new byte[5];
        bais.read(helloBytes);
        skipper.decryptInPlace(helloBytes);
        if(useBlockCipherSkipper) {
            skipper.skipDecrypt(bais, garbageByteCount);
        }else {
            BlockCipherSkipper.drainBytes(bais, garbageByteCount);
        }
        byte[] worldBytes = new byte[6];
        bais.read(worldBytes);
        skipper.decryptInPlace(worldBytes);
        return new String(helloBytes, StandardCharsets.UTF_8) + " " + new String(worldBytes, StandardCharsets.UTF_8);
    }

    public static Cipher cipherFromSharedSecret(int mode, Key key) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
            Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
            cipher.init(mode, key, new IvParameterSpec(key.getEncoded()));
            return cipher;
    }
}
