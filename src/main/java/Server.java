import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.List;
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
            Crypto crypto = new Crypto(1024);
            KeyPair t = crypto.generateKeyPair();
            myPrivateKey = t.getPrivate().getEncoded();
            myPublicKey = t.getPublic().getEncoded();

            /*
            Socket socket = ...
            byte[] myPublicKey = ...

            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            DataInputStream dIn = new DataInputStream(socket.getInputStream());

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

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
