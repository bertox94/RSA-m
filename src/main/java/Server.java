import javax.crypto.NoSuchPaddingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

public class Server {
    private static byte[] myPrivateKey;
    private static byte[] myPublicKey;
    private static Map<String, byte[]> publicKeyOfClients; //salva la coppia (username, key)

    public static byte[] getMyPublicKey() {
        return myPublicKey;
    }

    public static void main(String[] args) {
        try {
            Crypto crypto = getCrypto();

            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(myPrivateKey));
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(myPublicKey));

            /*
            Socket socket = ...
            byte[] myPublicKey = ...

            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            DataInputStream dIn = new DataInputStream(socket.getInputStream());

            //on the receiving end
            dOut.writeInt(myPublicKey.length); // write length of myPublicKey
            dOut.write(myPublicKey);           // write myPublicKey

            String username = dIn.readString();
            int length = dIn.readInt();                    // read length of incoming message
            if(length>0) {
                publicKey = new byte[length];
                dIn.readFully(publicKey, 0, publicKey.length); // read the message
                publicKeyOfClients.put(username, publicKey);
            }
            */


        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static Crypto getCrypto() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Crypto crypto = new Crypto(1024);
        KeyPair clientKey = crypto.generateKeyPair();
        myPrivateKey = clientKey.getPrivate().getEncoded();
        myPublicKey = clientKey.getPublic().getEncoded();
        return crypto;
    }
}