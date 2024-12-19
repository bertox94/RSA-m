import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Client {
    private static byte[] myPrivateKey;
    private static byte[] myPublicKey;
    private static byte[] publicKeyOfServer;

    public static void main(String[] args) {
        try {
            Crypto crypto = new Crypto(1024);
            KeyPair clientKey = crypto.generateKeyPair();
            myPrivateKey = clientKey.getPrivate().getEncoded();
            myPublicKey = clientKey.getPublic().getEncoded();

            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(myPrivateKey));
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(myPublicKey));


            // SCAMBIO CHIAVI
            /*
            Socket socket = ...
            byte[] myPublicKey = ...

            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            DataInputStream dIn = new DataInputStream(socket.getInputStream());

            dOut.writeInt(myPublicKey.length); // write length of myPublicKey
            dOut.write(myPublicKey);           // write myPublicKey

            int length = dIn.readInt();                    // read length of incoming key
            if(length>0) {
                publicKeyOfServer = new byte[length];
                dIn.readFully(publicKeyOfServer, 0, publicKeyOfServer.length); // read the key

            }
            */

            //ESEMPIO INVIO DA CLIENT A SERVER
            /*
            String msg = "TestInvio";

            String encryptedStringg = Base64.getEncoder()
                    .encodeToString(crypto.encrypt(msg, publicKeyOfServer));
            System.out.println("Encrypted string: " + encryptedStringg);
            */

            //ESEMPIO INVIO DA CLIENT A SERVER
            //INIZIO CODICE LATO SERVER:
            String msg = "TestInvio";
            String encryptedString = Base64.getEncoder().encodeToString(crypto.encrypt(msg, myPublicKey));
            System.out.println("Encrypted string: " + encryptedString);
            //FINE CODICE LATO SERVER

            String msgReceived = encryptedString;

            String decryptedString = crypto.decrypt(msgReceived, myPrivateKey);
            System.out.println("Decrypted string: " + decryptedString);


        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException |
                 InvalidKeyException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }


    }


}
