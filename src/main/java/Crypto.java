import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Crypto {
    private final KeyPairGenerator keyGen;
    private final KeyFactory keyFactory;
    private final Cipher cipher;

    public Crypto(int size) throws NoSuchPaddingException, NoSuchAlgorithmException {
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(size);
        keyFactory = KeyFactory.getInstance("RSA");
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return keyGen.generateKeyPair();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.close();
    }

    public byte[] encrypt(String data, byte[] publicKey) throws InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
        cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(publicKeySpec));
        return cipher.doFinal(data.getBytes());
    }

    public String decrypt(String data, byte[] privateKey) throws InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PKCS8EncodedKeySpec keySpecPr = new PKCS8EncodedKeySpec(privateKey);
        cipher.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(keySpecPr));
        return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes())));
    }
}
