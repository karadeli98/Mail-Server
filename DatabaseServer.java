
// A Java program for a Server 
import java.net.*;
import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DatabaseServer {
	public static String receivedContext;
	public static String sessionKey;
	public static int clientNonceValue;
	public static int serverNonceValue;
	public static File logFile;

	public static void main(String args[]) throws IOException, Exception {
		logFile = new File("Database_Log.txt");
		deleteFile(logFile);
		connectClient();

	}

	public static void connectClient() throws IOException, Exception {
		ServerSocket ss = new ServerSocket(3003);

		// connect it to client socket
		Socket s = ss.accept();
		System.out.println("Connection DB Server  established");

		// to send data to the client
		PrintStream ps = new PrintStream(s.getOutputStream());

		// to read data coming from the client
		BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

		// server executes continuously
		while (true) {

			String str, str1;

			// repeat as long as the client
			// does not send a null string

			// read from client
			while ((str = br.readLine()) != null) {
				receivedContext = str;
				thirdPhase();

				str1 = fourthPhase();
				ps.println(str1);

				str1 = fifthPhase(br.readLine());
				ps.println(str1);
			}

			// close connection
			ps.close();
			br.close();
			ss.close();
			s.close();

			// terminate application
			System.exit(0);

		} // end of while
	}

	public static void deleteFile(File file) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(file);
		writer.print("");
		writer.close();
	}

	public static void writeFile(File file, String output) throws IOException {
		FileWriter fr = new FileWriter(file, true);
		String message = currentTime();
		message = message + output;
		fr.write(message + "\n");
		fr.close();

	}

	public static String currentTime() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		return dtf.format(now);
	}

	public static void thirdPhase() throws Exception {

		String[] clientMessage = receivedContext.split(",");
		writeFile(logFile,
				" Alice->Database : " + "\"" + clientMessage[0] + "\", " + clientMessage[1] + ", " + clientMessage[2]);

		String ticket = decrypt(clientMessage[1]);
		String[] ticketArray = ticket.split(",");
		writeFile(logFile, " \"Ticket Decrpyted\" : " + "\"" + ticketArray[0] + "\", " + "\"" + ticketArray[1] + "\", "
				+ "[" + ticketArray[2] + "], " + Base64.getEncoder().encodeToString(ticketArray[3].getBytes()));

		sessionKey = ticketArray[3];
		// if (clientMessage[0].equalsIgnoreCase(ticketArray[0])) {
		// System.out.print("Client id is okey");
		// }

		clientNonceValue = Integer.parseInt(decryptSessionKey(clientMessage[2], sessionKey));
		writeFile(logFile, " \"Message Decrpyted\" : " + "N1 = " + "[" + clientNonceValue + "]");

		serverNonceValue = createNonceValue();

	}

	public static String fourthPhase() throws Exception {

		String newClientNonceValue = String.valueOf(clientNonceValue + 1);
		writeFile(logFile, " Database->Alice : " + "[" + newClientNonceValue + "], " + "[" + serverNonceValue + "]");
		String allNonceValues = newClientNonceValue + "," + String.valueOf(serverNonceValue);
		String encryptedMessage = encryptSessionKey(allNonceValues, sessionKey);
		writeFile(logFile, " Database->Alice : " + encryptedMessage);
		return encryptedMessage;

	}

	public static String fifthPhase(String clientResponse) throws Exception {
		String receivedMessage = decryptSessionKey(clientResponse, sessionKey);
		writeFile(logFile, " Alice->Database : " + clientResponse);
		int nonceValue1 = Integer.parseInt(receivedMessage);
		writeFile(logFile, " \"Message Decrpyted\" : " + "[" + receivedMessage + "]");

		if (serverNonceValue + 1 != nonceValue1) {
			System.out.print("authentication not completed ");
		} else {
			writeFile(logFile, " Database->Alice : " + "\"Authentication is completed!\"");
			return "Authentication is completed";
		}

		return "Authentication not completed";

	}

	public static String decrypt(String encryptText) throws Exception {
		String privateKey = getPrivateKey("DatabasePrivateKey");
		byte[] decodedKey = Base64.getDecoder().decode(encryptText);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
		PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
		Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decrypted = cipherDecrypt.doFinal(decodedKey);
		return new String(decrypted);
	}

	public static int createNonceValue() {
		Random random = new Random();
		int nonce = random.nextInt();
		return nonce;

	}

	public static String encryptSessionKey(String plainText, String secretKey) throws Exception {

		byte[] clean = plainText.getBytes();
		SecretKey scKey = stringToKey(secretKey);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, scKey);
		byte[] encrypted = cipher.doFinal(clean);

		return (Base64.getEncoder().encodeToString(encrypted));

	}

	public static SecretKey stringToKey(String md5String) {
		byte[] decodedKey = Base64.getDecoder().decode(md5String);
		// rebuild key using SecretKeySpec
		SecretKey AesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return AesKey;
	}

	public static String decryptSessionKey(String encryptedText, String secretKey) throws Exception {

		byte[] encText = Base64.getDecoder().decode(encryptedText);

		SecretKey scKey = stringToKey(secretKey);
		Cipher cipherDecrypt = Cipher.getInstance("AES");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, scKey);
		byte[] decrypted = cipherDecrypt.doFinal(encText);

		return new String(decrypted);
	}

	public static String getPrivateKey(String keyFile) throws FileNotFoundException {
		File privateKeyFile = new File("keys/" + keyFile);
		String keyContext = readFile(privateKeyFile);
		String firstMessage = "-----BEGIN PRIVATE KEY-----";
		String lastMessage = "-----END PRIVATE KEY-----";
		int firstIndex = keyContext.indexOf(firstMessage);
		int lastIndex = keyContext.indexOf(lastMessage);
		String originalKey = keyContext.substring(firstIndex + (firstMessage.length()), lastIndex).replaceAll("\\r|\\n",
				"");
		return originalKey;

	}

	public static String readFile(File file) throws FileNotFoundException {
		Scanner myReader = new Scanner(file);
		String content = "";
		while (myReader.hasNextLine()) {
			String data = myReader.nextLine();
			content += data;
		}
		myReader.close();
		return content;
	}
}
