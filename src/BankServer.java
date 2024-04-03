import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class BankServer {
    private static final int PORT = 12345;
    private static Map<String, String> userDatabase = new ConcurrentHashMap<>();
    private static Map<String, SecretKey> masterSecrets = new ConcurrentHashMap<>();
    private static Map<String, Double> accountBalances = new ConcurrentHashMap<>();
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String keyString = "mySimpleSharedKey"; // Ensure this is sufficiently secure and random for production use
    private static final byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
    private static final SecretKey sharedKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES"); // Using AES-128. Adjust the length as necessary.

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
                String username = null;

                while ((request = in.readLine()) != null) {
                    switch (request) {
                        case "REGISTER":
                            username = in.readLine();
                            String password = in.readLine();
                            String registrationResult = registerUser(username, password);
                            out.println(registrationResult);
                            break;
                        case "LOGIN":
                            username = in.readLine();
                            password = in.readLine();
                            boolean loggedIn = loginUser(username, password);
                            out.println(loggedIn ? "LOGGED IN" : "LOGIN FAILED");
                            break;
                        case "QUIT":
                            return; // Exit the thread
                        case "VIEW BALANCE":
                            if (username != null && userDatabase.containsKey(username)) {
                                double balance = accountBalances.getOrDefault(username, 0.0);
                                out.println("Your account balance is: $" + balance);
                            } else {
                                out.println("ERROR: You need to log in first.");
                            }
                            break;
                        case "DEPOSIT":
                            double amount = Double.parseDouble(in.readLine());
                            if (username != null && userDatabase.containsKey(username)) {
                                accountBalances.merge(username, amount, Double::sum);
                                out.println("Deposit successful. New balance: $" + accountBalances.get(username));
                            } else {
                                out.println("ERROR: You need to log in first.");
                            }
                            break;
                        case "WITHDRAW":
                            amount = Double.parseDouble(in.readLine());
                            if (username != null && userDatabase.containsKey(username)) {
                                double currentBalance = accountBalances.getOrDefault(username, 0.0);
                                if (amount <= currentBalance) {
                                    accountBalances.put(username, currentBalance - amount);
                                    out.println("Withdrawal successful. New balance: $" + accountBalances.get(username));
                                } else {
                                    out.println("ERROR: Insufficient funds.");
                                }
                            } else {
                                out.println("ERROR: You need to log in first.");
                            }
                            break;
                        default:
                            out.println("ERROR: Unknown request.");
                            break;
                    }
                }
            } catch (IOException ex) {
                System.out.println("Server exception: " + ex.getMessage());
                ex.printStackTrace();
            }
        }

        private synchronized String registerUser(String username, String password) {
            if (userDatabase.containsKey(username)) {
                return "ERROR: User already exists. Please try a different username.";
            } else {
                userDatabase.put(username, password); // In production, use hashed password
                accountBalances.put(username, 0.0);
                return "SUCCESS: User registered successfully.";
            }
        }

        private synchronized boolean loginUser(String username, String password) {
            String storedPassword = userDatabase.get(username);
            return storedPassword != null && storedPassword.equals(password);
        }
    }
}
