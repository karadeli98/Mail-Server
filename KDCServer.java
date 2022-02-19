import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class KDCServer {
	private static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
	private static final String NUMBER = "0123456789";
	private static final String DATA_FOR_RANDOM_STRING = CHAR_LOWER + NUMBER;
	public static String aliceRequest;
	public static LocalTime kdcMessageTime;
	public static String sessionKey;
	public static File logFile;

	public static void main(String args[]) throws IOException, Exception {

		logFile = new File("KDC_Log.txt");
		deleteFile(logFile);
		System.out.println("This command will take 30 seconds please wait");
		createKeyPairs();
		String password = generateRandomString();
		System.out.println("KDC password is -> " + password);
		String hashPassword = getSHA(password);
		File passwordFile = new File("passwd");
		writeFile(passwordFile, hashPassword);
		writeToLogFile(logFile, " [" + password + "]");
		System.out.println("Command finish succesfuly");
		connectClient();

	}

	
	public static void connectClient() throws IOException, Exception {
		// Create server Socket 
		ServerSocket ss = new ServerSocket(3000);

		// connect it to client socket
		Socket s = ss.accept();

		

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

				aliceRequest = str;
				str1 = firstPhase();

				// send to client
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

	public static String firstPhase() throws Exception {
		String[] aliceRequestArray = aliceRequest.split(",");

		writeToLogFile(logFile, " Alice->KDC : " + "\"" + aliceRequestArray[0] + "\", " + aliceRequestArray[1]);

		String decryptedText = decrypt(aliceRequestArray[1], getPrivateKey("KdcPrivateKey"));

		String[] messageArray = decryptedText.split(",");

		writeToLogFile(logFile, " Message Decrypted : " + "\"" + messageArray[0] + "\", " + "[" + messageArray[1]
				+ "], " + "\"" + messageArray[2] + "\", " + "[" + messageArray[3] + "]");

		String password = messageArray[1];
		if (verifyPassword(password)) {
			writeToLogFile(logFile, " KDC->Alice : \"Password Verified\"");
			return secondPhase(decryptedText);

		} else {
			writeToLogFile(logFile, " KDC->Alice : \"Password Denied\"");
			return "Verification failed";
		}

	}

	public static void deleteFile(File file) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(file);
		writer.print("");
		writer.close();
	}

	public static String currentTime() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		return dtf.format(now);
	}

	public static String secondPhase(String decryptedText) throws Exception {
		String ticket = createTicket(decryptedText);
		String toClient = encryptionAliceKey(decryptedText);

		writeToLogFile(logFile, " KDC->Alice : " + toClient + ", " + ticket);
		toClient = toClient + "," + ticket;

		return toClient;
	}

	public static void writeToLogFile(File file, String output) throws IOException {
		FileWriter fr = new FileWriter(file, true);

		String message = currentTime() + output;

		fr.write(message + "\n");
		fr.close();

	}

	public static void writeFile(File file, String output) throws IOException {
		FileWriter fr = new FileWriter(file, true);
		fr.write(output + "\n");
		fr.close();

	}

	public static String getSHA(String password) {
		try {

			MessageDigest md = MessageDigest.getInstance("SHA-1");

			byte[] messageDigest = md.digest(password.getBytes());

			BigInteger no = new BigInteger(1, messageDigest);
			StringBuilder hexString = new StringBuilder(no.toString(16));
			while (hexString.length() < 32) {

				hexString.insert(0, '0');

			}
			return hexString.toString();
		}

		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}

	public static void createKeyPairs() throws IOException {
		File keys = new File("keys");
		File cert = new File("cert");
		cert.mkdir();
		keys.mkdir();
		String privateKeyFile = "";
		String certificateFile = "";
		String keyStore = "";
		String alias = "";

		for (int i = 0; i < 5; i++) {
			if (i == 0) {
				privateKeyFile = "KdcPrivateKey";
				certificateFile = "KdcCertificate";
				keyStore = "KdcStore";
				alias = "KdcAlias";

			} else if (i == 1) {
				privateKeyFile = "AlicePrivateKey";
				certificateFile = "AliceCertificate";
				keyStore = "clientStore";
				alias = "clientAlias";
			} else if (i == 2) {
				privateKeyFile = "MailPrivateKey";
				certificateFile = "MailCertificate";
				keyStore = "mailStore";
				alias = "mailAlias";
			} else if (i == 3) {
				privateKeyFile = "WebPrivateKey";
				certificateFile = "WebCertificate";
				keyStore = "webStore";
				alias = "webAlias";
			} else if (i == 4) {
				privateKeyFile = "DatabasePrivateKey";
				certificateFile = "DatabaseCertificate";
				keyStore = "databaseStore";
				alias = "databaseAlias";
			}

			String keyPair = "keytool -genkeypair -dname \"cn=furkan, ou=Java, o=Oracle, c=US\"" + " -alias " + alias
					+ " -keystore " + keyStore + ".jks -storepass  123456" + " -validity 180 -keyalg RSA -keysize 2048 -keypass 123456";
			commandExecute(keyPair);
			String jksToPk12 = "keytool -importkeystore -dname \"cn=furkan, ou=Java, o=Hacettepe, c=TR\""
					+ " -srckeystore " + keyStore + ".jks -srcstoretype JKS" + " -srcalias " + alias + " -destkeystore "
					+ keyStore + ".p12 -deststoretype PKCS12"
					+ " -deststorepass 123456 -destkeypass 123456 -srcstorepass 123456";
			commandExecute(jksToPk12);
			String getPrivateKey = "openssl pkcs12 -in " + keyStore
					+ ".p12  -nodes -nocerts -password pass:123456 -out keys/" + privateKeyFile;
			commandExecute(getPrivateKey);

			String createCSR = "keytool -certreq -keystore " + keyStore + ".jks -alias " + alias
					+ " -keyalg rsa -file CSR.csr -storepass 123456";
			commandExecute(createCSR);

			String createCert = "keytool -gencert -rfc -alias KdcAlias"
					+ " -keystore KdcStore.jks -keypass 123456 -outfile cert/" + certificateFile
					+ ".cer -infile CSR.csr -storepass 123456";
			commandExecute(createCert);
			if (i != 0) {
				commandExecute("rm " + keyStore + ".jks");
				commandExecute("rm " + keyStore + ".p12");
			}

		}
		commandExecute("rm CSR.csr");
		commandExecute("rm KdcStore.jks");
		commandExecute("rm KdcStore.p12");

	}

	public static String generateRandomString() throws FileNotFoundException {

		PrintWriter writer = new PrintWriter("passwd");
		writer.print("");
		writer.close();

		StringBuilder sb = new StringBuilder(10);
		for (int i = 0; i < 10; i++) {
			Random random = new Random();

			// 0-62 (exclusive), random returns 0-61
			int rndCharAt = random.nextInt(DATA_FOR_RANDOM_STRING.length());
			char rndChar = DATA_FOR_RANDOM_STRING.charAt(rndCharAt);

			sb.append(rndChar);

		}

		return sb.toString();

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

	public static String decrypt(String encryptText, String privateKey) throws Exception {
		byte[] decodedKey = Base64.getDecoder().decode(encryptText);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
		PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
		Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decrypted = cipherDecrypt.doFinal(decodedKey);
		return new String(decrypted);
	}

	public static String createTicket(String decryptedText) throws Exception {
		byte[] encryptedText;
		String _sessionKey = sessionKeyGenerator();
		sessionKey = _sessionKey;
		LocalTime timestamp = LocalTime.now();
		kdcMessageTime = timestamp;
		String[] aliceContextArray = decryptedText.split(",");
		String clientId = aliceContextArray[0];
		String serverName = aliceContextArray[2];
		String context = clientId + "," + serverName + "," + timestamp + "," + sessionKey;
		if (serverName.equalsIgnoreCase("mail")) {
			encryptedText = Encryption(context, getPublicKey("MailCertificate"));
		} else if (serverName.equalsIgnoreCase("database")) {
			encryptedText = Encryption(context, getPublicKey("DatabaseCertificate"));
		} else {
			encryptedText = Encryption(context, getPublicKey("WebCertificate"));
		}
		String enc = Base64.getEncoder().encodeToString(encryptedText);
		return enc;
	}

	public static boolean verifyPassword(String password) throws FileNotFoundException {
		File passwordFile = new File("passwd");
		String hashedPassword = getSHA(password);
		String currentPassword = readFile(passwordFile);
		if (hashedPassword.equals(currentPassword)) {
			return true;
		}
		return false;

	}

	public static String encryptionAliceKey(String decryptedText) throws Exception {

		String[] aliceContextArray = decryptedText.split(",");
		String serverName = aliceContextArray[2];
		String context = sessionKey + "," + serverName + "," + kdcMessageTime;
		writeToLogFile(logFile, " KDC->Alice : " + Base64.getEncoder().encodeToString(sessionKey.getBytes()) + ", "
				+ "\"" + serverName + "\", " + "[" + kdcMessageTime + "]");
		byte[] encryptedText = Encryption(context, getPublicKey("AliceCertificate"));
		String enc = Base64.getEncoder().encodeToString(encryptedText);
		return enc;

	}

	public static String sessionKeyGenerator() throws NoSuchAlgorithmException {
		SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());

	}

	public static SecretKey stringToKey(String md5String) {
		byte[] decodedKey = Base64.getDecoder().decode(md5String);
		// rebuild key using SecretKeySpec
		SecretKey AesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return AesKey;
	}

	public static String encryptSessionKey(String plainText, String secretKey) throws Exception {

		byte[] clean = plainText.getBytes();
		SecretKey scKey = stringToKey(secretKey);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, scKey);
		byte[] encrypted = cipher.doFinal(clean);

		return (Base64.getEncoder().encodeToString(encrypted));

	}

	public static String decryptSessionKey(String encryptedText, String secretKey) throws Exception {

		byte[] encText = Base64.getDecoder().decode(encryptedText);

		SecretKey scKey = stringToKey(secretKey);
		Cipher cipherDecrypt = Cipher.getInstance("AES");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, scKey);
		byte[] decrypted = cipherDecrypt.doFinal(encText);

		return new String(decrypted);
	}

}
