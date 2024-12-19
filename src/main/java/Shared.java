import javax.crypto.NoSuchPaddingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class Shared {
    private static KeyPair initializeSecurity() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Crypto crypto = new Crypto(1024);
        KeyPair key = crypto.generateKeyPair();
        return key;
    }
}
