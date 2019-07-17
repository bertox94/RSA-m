import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Main {

    private static KeyPair generateKeyPair(int size) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(size);
        return keyGen.generateKeyPair();
    }

    private static void writeToFile(String path, Key key) throws IOException {
        File f = new File(path);
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key.getEncoded());
        fos.close();
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, NoSuchPaddingException {

        KeyPair keyPair = generateKeyPair(1024);

        writeToFile(Constants.pathToPrivateKey, keyPair.getPrivate());
        writeToFile(Constants.pathToPublicKey, keyPair.getPublic());
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println();

        RSAUtil.example("Barbagianni");

    }
}
