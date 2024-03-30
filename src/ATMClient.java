import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.io.*;
import java.net.*;
import java.util.concurrent.ConcurrentHashMap;

public class ATMClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String keyString = "mySimpleSharedKey"; // Ensure this is sufficiently secure and random for production use
    private static final byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
    private static final SecretKey sharedKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("Connected to the bank server");
            System.out.println("Do you want to (1) Register or (2) Login? (Enter 1 or 2)");
            String option = stdIn.readLine();

            if ("1".equals(option)) {
                boolean isRegistered = false;
                while (!isRegistered) {
                    System.out.println("Enter username for registration:");
                    String username = stdIn.readLine();
                    System.out.println("Enter password for registration:");
                    String password = stdIn.readLine();

                    out.println("REGISTER");
                    out.println(username);
                    out.println(password);

                    String serverResponse = in.readLine();
                    System.out.println(serverResponse); // Server response printed out to the console

                    // If the user already exists, re-prompt for registration details
                    if (!serverResponse.startsWith("ERROR")) {
                        isRegistered = true;
                    }
                }
            } else if ("2".equals(option)) {
                // Login process
                System.out.println("Enter username for login:");
                String username = stdIn.readLine();
                System.out.println("Enter password for login:");
                String password = stdIn.readLine();

                out.println("LOGIN");
                out.println(username);
                out.println(password);

                String serverResponse = in.readLine();
                System.out.println(serverResponse); // Should be "LOGGED IN" if successful

                if ("LOGGED IN".equals(serverResponse)) {
                    performKeyDistributionProtocol(out, in);
                }
            }

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + SERVER_ADDRESS);
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    SERVER_ADDRESS + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void performKeyDistributionProtocol(PrintWriter out, BufferedReader in) throws IOException {
        try {
            // Step 1: Generate client nonce (nonce_C) and send to server
            String nonce_C = generateNonce();
            out.println(encrypt(nonce_C, sharedKey));

            // Step 2: Receive server's nonce and decrypt it
            String encryptedNonce_S = in.readLine();
            String nonce_S = decrypt(encryptedNonce_S, sharedKey);

            // Step 3: Derive Master Secret from nonces
            SecretKey masterSecret = deriveMasterSecret(nonce_C, nonce_S, sharedKey);
            System.out.println("Master Secret established.");

            // Derive Data Encryption Key and MAC Key from Master Secret
            SecretKey[] keys = deriveKeysFromMasterSecret(masterSecret);
            SecretKey encryptionKey = keys[0];
            SecretKey macKey = keys[1];
            System.out.println("Data Encryption Key and MAC Key derived.");

            // Indicate completion
            System.out.println("KEY DISTRIBUTION COMPLETE");

        } catch (Exception e) {
            throw new IOException("Key distribution failed", e);
        }
    }

    private static String generateNonce() {
        // Securely generate and return a nonce
        return Long.toString(new SecureRandom().nextLong());
    }

    private static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(original);
    }

    private static SecretKey deriveMasterSecret(String nonce_C, String nonce_S, SecretKey sharedKey) throws Exception {
        // Derive Master Secret (example method, adjust as needed)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest((nonce_C + nonce_S).getBytes());
        return new SecretKeySpec(Arrays.copyOf(hash, 16), "AES"); // Using first 128 bits of hash
    }

    private static SecretKey[] deriveKeysFromMasterSecret(SecretKey masterSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(masterSecret.getEncoded());

        // Split the hash in half; use the first part for the encryption key, the second part for the MAC key
        byte[] encryptionKeyBytes = Arrays.copyOfRange(hash, 0, hash.length / 2);
        byte[] macKeyBytes = Arrays.copyOfRange(hash, hash.length / 2, hash.length);

        // Create SecretKey objects from the byte arrays
        SecretKey encryptionKey = new SecretKeySpec(encryptionKeyBytes, "AES");
        SecretKey macKey = new SecretKeySpec(macKeyBytes, "AES"); // Use "HmacSHA256" for HMAC operations

        return new SecretKey[]{encryptionKey, macKey};
    }
}
