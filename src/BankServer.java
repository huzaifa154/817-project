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

public class BankServer {
    private static final int PORT = 12345;
    private static Map<String, String> userDatabase = new HashMap<>();
    private static Map<String, SecretKey> masterSecrets = new ConcurrentHashMap<>();
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String keyString = "mySimpleSharedKey"; // Ensure this is sufficiently secure and random for production use
    private static final byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
    private static final SecretKey sharedKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES"); // Using AES-128. Adjust the length as necessary.
    private static Map<String, Double> accountBalances = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Bank Server is listening on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new ClientHandler(clientSocket).start();
            }
        } catch (IOException ex) {
            System.out.println("Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
        
                String request;
                String username = null; // You might already have this for handling REGISTER and LOGIN
        
                // Keep listening for client requests on the same connection
                while ((request = in.readLine()) != null) {
                    switch (request) {
                        // Existing cases: REGISTER, LOGIN, QUIT
                        case "REGISTER":
                            username = in.readLine();
                            String password = in.readLine(); // Hash in a real system
                            String registrationResult = registerUser(username, password);
                            out.println(registrationResult);
                            break;
                        case "LOGIN":
                            username = in.readLine();
                            password = in.readLine();
                            boolean loggedIn = loginUser(username, password);
                            out.println(loggedIn ? "LOGGED IN" : "LOGIN FAILED");
                            if (loggedIn) {
                                // Now that the user is logged in, initiate the key distribution protocol
                                performKeyDistributionProtocol(in, out, username);
                            }
                            break;
                        case "QUIT":
                            // Existing quit logic
                            return; // Exit the thread
                        // Add the new cases here for VIEW BALANCE, DEPOSIT, and WITHDRAW
                        case "VIEW BALANCE":
                            double balance = accountBalances.getOrDefault(username, 0.0);
                            out.println("Your account balance is: $" + balance);
                            break;
                        case "DEPOSIT":
                            double amount = Double.parseDouble(in.readLine());
                            accountBalances.merge(username, amount, Double::sum);
                            out.println("Deposit successful. New balance: $" + accountBalances.get(username));
                            break;
                        case "WITHDRAW":
                            amount = Double.parseDouble(in.readLine());
                            double currentBalance = accountBalances.getOrDefault(username, 0.0);
                            if (amount <= currentBalance) {
                                accountBalances.put(username, currentBalance - amount);
                                out.println("Withdrawal successful. New balance: $" + accountBalances.get(username));
                            } else {
                                out.println("ERROR: Insufficient funds.");
                            }
                            break;
                        // Handle unknown requests or keep alive messages
                        default:
                            // Unknown request logic
                            break;
                    }
                }
        
            } catch (IOException ex) {
                System.out.println("Server exception: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        

        private void performKeyDistributionProtocol(BufferedReader in, PrintWriter out, String username) throws IOException {
            try {
                // Step 1: Generate server nonce (nonce_S)
                String nonce_S = generateNonce();

                // Step 2: Send server nonce to client encrypted with the shared key
                String encryptedNonce_S = encrypt(nonce_S, sharedKey); // sharedKey would be a pre-established symmetric key
                out.println(encryptedNonce_S);

                // Step 3: Receive client nonce (nonce_C) encrypted with the shared key
                String encryptedNonce_C = in.readLine();
                String nonce_C = decrypt(encryptedNonce_C, sharedKey);

                // Step 4: Derive Master Secret using both nonces (and potentially the shared key)
                SecretKey masterSecret = deriveMasterSecret(nonce_C, nonce_S, sharedKey);

                // Step 5: Store the Master Secret with the session identified by username
                storeMasterSecret(username, masterSecret);

                // Derive Data Encryption Key and MAC Key from Master Secret
                SecretKey[] keys = deriveKeysFromMasterSecret(masterSecret);
                SecretKey encryptionKey = keys[0];
                SecretKey macKey = keys[1];
                System.out.println("Data Encryption Key and MAC Key derived.");

                // Indicate to the client that the key distribution protocol was successful
                out.println("KEY DISTRIBUTION COMPLETE");

            } catch (Exception e) {
                throw new IOException("Key distribution failed", e);
            }
        }

        private String generateNonce() {
            // Securely generate and return a nonce
            return Long.toString(new SecureRandom().nextLong());
        }

        private String encrypt(String data, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }

        private String decrypt(String data, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));
            return new String(original);
        }

        private SecretKey deriveMasterSecret(String nonce_C, String nonce_S, SecretKey sharedKey) throws Exception {
            // Derive Master Secret (example method, adjust as needed)
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest((nonce_C + nonce_S).getBytes());
            return new SecretKeySpec(Arrays.copyOf(hash, 16), "AES"); // Using first 128 bits of hash
        }

        private void storeMasterSecret(String username, SecretKey masterSecret) {
            // Store the master secret in the map, associated with the username
            masterSecrets.put(username, masterSecret);
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

        private synchronized String registerUser(String username, String password) {
            if (userDatabase.containsKey(username)) {
                // User already exists
                return "ERROR: User already exists. Please try a different username.";
            } else {
                // Here is where you would hash the password in a real system
                userDatabase.put(username, password);
                // Registration successful
                return "SUCCESS: User registered successfully.";
            }
        }

        private synchronized boolean loginUser(String username, String password) {

            String storedPassword = userDatabase.get(username);
            return storedPassword != null && storedPassword.equals(password);
        }
    }
}
