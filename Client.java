import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {
	public static String sessionKey;
	public static String serverName;
	public static String password;
	public static String kdcMessage;
	public static String ticket;
	public static File logFile;
	public static int nonceValue;
	public static int serverNonceValue;
	public static boolean decision = true;

	public static void main(String args[]) throws IOException, Exception {
		logFile = new File("Alice_Log.txt");
		deleteFile(logFile);
		connectKDC();
	}

	public static void connectKDC() throws IOException, Exception {
		Socket s = new Socket("localhost", 3000);

		// send data to server
		DataOutputStream dos = new DataOutputStream(s.getOutputStream());
		// to read data coming from server
		BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
		// to read data from the keyboard
		BufferedReader kb = new BufferedReader(new InputStreamReader(System.in));

		String str, str1;
		while (decision) {

			System.out.print("Enter a password: ");
			password = kb.readLine(); //
			while (true) {
				System.out.print("Enter server name: ");
				serverName = kb.readLine();
				if (serverName.equalsIgnoreCase("Mail") || serverName.equalsIgnoreCase("Web")
						|| serverName.equalsIgnoreCase("Database")) {
					break;
				}
			}
			// send to the server
			dos.writeBytes(firstPhase() + "\n");
			// receive from the server
			str1 = br.readLine();
			if (str1.equals("Verification failed")) {
				writeFile(logFile, " KDC->Alice : " + "\"" + "Password Denied" + "\"");
				System.out.println("Verification failed");
			} else {
				kdcMessage = str1;
				writeFile(logFile, " KDC->Alice : " + "\"" + "Password Verified" + "\"");

				connectOtherServer(serverName);
			}

			System.out.print("Do u want to contiune communication with KDC ? (Yes /No)");
			String karar = kb.readLine();
			if (karar.equals("No")) {
				decision = false;
			}
		}

		// close connection.
		dos.close();
		br.close();
		kb.close();
		s.close();
	}

	public static void connectOtherServer(String serverName) throws IOException, Exception {

		if (serverName.equalsIgnoreCase("Mail")) {
			connectServer(3001);
		} else if (serverName.equalsIgnoreCase("Web")) {
			connectServer(3002);

		} else {// Database
			connectServer(3003);
		}

	}

	public static void connectServer(int portNumber) throws IOException, Exception {
		Socket s = new Socket("localhost", portNumber);

		// send data to server
		DataOutputStream dos = new DataOutputStream(s.getOutputStream());
		// to read data coming from server
		BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
		// to read data from the keyboard

		String str1;

		// send to the server
		dos.writeBytes(secondPhase() + "\n");

		// receive from the server
		str1 = br.readLine();
		writeFile(logFile, " " + serverName + "->Alice : " + str1);
		fourthPhase(str1);

		dos.writeBytes(fifthPhase() + "\n");
		str1 = br.readLine();
		writeFile(logFile, " " + serverName + "->Alice : " + "\"" + str1 + "\"");

		// close connection.

		s.close();

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

	public static String firstPhase() throws Exception {

		LocalTime timestamp = LocalTime.now();

		String id = "Alice";

		String context = id + "," + password + "," + serverName + "," + timestamp;

		writeFile(logFile, " Alice->KDC : " + "\"" + id + "\", " + "[" + password + "], " + "\"" + serverName + "\", "
				+ "[" + timestamp + "]");

		byte[] encryptedContext = Encryption(context, getPublicKey("KdcCertificate"));
		String enc = Base64.getEncoder().encodeToString(encryptedContext);

		writeFile(logFile, " Alice->KDC : " + "\"" + id + "\", " + enc);

		String allMessage = id + "," + enc;
		return allMessage;
	}

	public static String secondPhase() throws Exception {

		String[] kdcMessageArray = kdcMessage.split(",");

		writeFile(logFile, " KDC->Alice : " + kdcMessageArray[0] + ", " + kdcMessageArray[1]);

		ticket = kdcMessageArray[1];
		byte[] encryptedText = Base64.getDecoder().decode(kdcMessageArray[0]);
		String decryptedText = decrypt(encryptedText, getPrivateKey("AlicePrivateKey"));
		String[] decryptedArray = decryptedText.split(",");

		writeFile(logFile, " Message Decrypted : " + Base64.getEncoder().encodeToString(decryptedArray[0].getBytes())
				+ ", " + "\"" + decryptedArray[1] + "\", " + "[" + decryptedArray[2] + "]");
		sessionKey = decryptedArray[0];
		return thirdPhase();

	}

	public static String thirdPhase() throws Exception {
		String id = "Alice";
		nonceValue = createNonceValue();
		String encryptSession = encryptSessionKey(String.valueOf(nonceValue), sessionKey);
		writeFile(logFile, " Alice->" + serverName + " : " + "\"" + id + "\", " + "[" + nonceValue + "]");
		String allMessage = id + "," + ticket + "," + encryptSession;
		writeFile(logFile, " Alice->" + serverName + " : " + "\"" + id + "\", " + ticket + ", " + encryptSession);
		return allMessage;
	}

	public static void fourthPhase(String serverResponse) throws Exception {
		String receivedMessage = decryptSessionKey(serverResponse, sessionKey);
		String[] receivedArray = receivedMessage.split(",");
		int nonceValue1 = Integer.parseInt(receivedArray[0]);
		serverNonceValue = Integer.parseInt(receivedArray[1]);
		if (nonceValue + 1 != nonceValue1) {
			System.out.print("Nonce values are different");
		} else {
			writeFile(logFile, " Message Decrpyted : " + "N1 is OK, N2 = " + "[" + serverNonceValue + "]");
		}

	}

	public static String fifthPhase() throws Exception {

		String serverNonceValueResponse = String.valueOf(serverNonceValue + 1);
		writeFile(logFile, " Alice->" + serverName + " : " + "[" + serverNonceValueResponse + "]");

		String encryptedMessage = encryptSessionKey(serverNonceValueResponse, sessionKey);

		writeFile(logFile, " Alice->" + serverName + " : " + encryptedMessage);
		return encryptedMessage;
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

	public static String getPublicKey(String certificateFile) throws IOException {
		String command = "openssl x509 -inform pem -in cert/" + certificateFile
				+ ".cer -pubkey -noout > certificate_publickey.pem";
		commandExecute(command);
		File publicFile = new File("certificate_publickey.pem");
		String publicKey = readFile(publicFile);
		String firstMessage = "-----BEGIN PUBLIC KEY-----";
		String lastMessage = "-----END PUBLIC KEY-----";
		int firstIndex = publicKey.indexOf(firstMessage);
		int lastIndex = publicKey.indexOf(lastMessage);

		String originalKey = publicKey.substring(firstIndex + (firstMessage.length()), lastIndex).replaceAll("\\r|\\n",
				"");
		return originalKey;
		commandExecute("rm certificate_publickey.pem");

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

	public static void commandExecute(String command) throws IOException {

		ProcessBuilder processBuilder = new ProcessBuilder();

		processBuilder.command("/bin/bash", "-c", "" + command);

		try {

			Process process = processBuilder.start();

			process.waitFor();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

	}

	public static byte[] Encryption(String plainText, String publicKey) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
		RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
		byte[] clean = plainText.getBytes();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] encrypted = cipher.doFinal(clean);
		return encrypted;

	}

	public static String decrypt(byte[] encryptedText, String privateKey) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
		PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
		Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decrypted = cipherDecrypt.doFinal(encryptedText);
		return new String(decrypted);
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

	public static int createNonceValue() {
		Random random = new Random();
		int nonce = random.nextInt();
		return nonce;

	}

}
