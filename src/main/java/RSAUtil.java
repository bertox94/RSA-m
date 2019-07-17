import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class RSAUtil {

    private static byte[] encrypt(String data, PublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    private static String decrypt(String data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes())));
    }

    static void example(String data) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {


        Path path = Paths.get(Constants.pathToPrivateKey);
        byte[] privateKeyBytes = Files.readAllBytes(path);
        path = Paths.get(Constants.pathToPublicKey);
        byte[] publicKeyBytes = Files.readAllBytes(path);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PKCS8EncodedKeySpec keySpecPr = new PKCS8EncodedKeySpec(privateKeyBytes);

        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPr);

        //Theoretical explanation:
        // The following is the case where I (Bob) encrypt the text
        // with the public key of Alice, and then she decrypts the cyphertext
        // using his own private key.
        // This forbids to a evil user in between to read the content of the text,
        // (because he miss the unique private Alice's key), however he can still spoof me
        // (by using my ip for example).
        // To achieve full protection I need in addition to encrypt the cyphertext
        // with my private key, so in this way, Alice using my public key
        // can be sure that this message was sent from me (because only I have my private key)
        // To recap: when Bob encrypts the message with Alice's public key, he knows that
        // only Alice can read it. When Bob encrypts the text with his own private key
        // he knows that whoever read the message it is sure that it was sent exactly by Bob.
        // When Bob uses both, then the action is combined.
        String encryptedString = Base64.getEncoder().encodeToString(encrypt(data, publicKey));
        System.out.println("Encrypted string: " + encryptedString);

        String decryptedString = decrypt(encryptedString, privateKey);
        System.out.println("Decrypted string: " + decryptedString);

    }

}
