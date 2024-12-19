import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Client {
    private static byte[] clientPrivateKey;
    private static byte[] clientPublicKey;
    private static byte[] publicKeyOfServer;

    public static void main(String[] args) {
        try {
            Crypto crypto = getCrypto();

            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(clientPrivateKey));
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(clientPublicKey));


            // SCAMBIO CHIAVI
            /*
            Socket socket = ...

            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            DataInputStream dIn = new DataInputStream(socket.getInputStream());
            
            //on the receiving end...
            dOut.writeInt(clientPublicKey.length); // write length of clientPublicKey
            dOut.write(clientPublicKey);           // write clientPublicKey

            int length = dIn.readInt();                    // read length of incoming key
            if(length>0) {
                publicKeyOfServer = new byte[length];
                dIn.readFully(publicKeyOfServer, 0, publicKeyOfServer.length); // read the key

            }
            */

            //ESEMPIO INVIO DA CLIENT A SERVER
            /*
            String msg = "TestInvio";
            String encryptedString = Base64.getEncoder().encodeToString(crypto.encrypt(msg, serverPublicKey));
            System.out.println("Encrypted string: " + encryptedString);
            */

            //ESEMPIO INVIO DA SERVER A CLIENT
            //INIZIO CODICE LATO SERVER:
            String msg = "TestInvio";
            //La chiave viene selezionata dalla Map<String, byte[]> lato server
            String encryptedString = Base64.getEncoder().encodeToString(crypto.encrypt(msg, clientPublicKey));
            System.out.println("Encrypted string: " + encryptedString);
            //FINE CODICE LATO SERVER

            String msgReceived = encryptedString;

            String decryptedString = crypto.decrypt(msgReceived, clientPrivateKey);
            System.out.println("Decrypted string: " + decryptedString);


        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException |
                 InvalidKeyException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static Crypto getCrypto() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Crypto crypto = new Crypto(1024);
        KeyPair clientKey = crypto.generateKeyPair();
        clientPrivateKey = clientKey.getPrivate().getEncoded();
        clientPublicKey = clientKey.getPublic().getEncoded();
        return crypto;
    }

}
