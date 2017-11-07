import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;


public class ServerOperation extends UnicastRemoteObject implements RMIInterface{
	private static final long serialVersionUID = 1L;
	private volatile static RMIClientInterface client;
	private static PrivateKey privateKey;
	public static PublicKey publicKey;
	static PublicKey clientPublicKey;
	static SecretKey macKey;
	static byte[] macKeyBytes;
	public static boolean confidentiality, integrity, authentication = false;

	protected ServerOperation() throws RemoteException {
		super();
	}

	@Override
	public void sendMessageServerEncrypted(byte[] encryptedKey, byte[] encryptedText) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
	    Cipher aesCipher = Cipher.getInstance("AES");
	    
	    SecretKey originalKey = decryptKey(encryptedKey);
		
		aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
		// Decrypt the ciphertext
	    byte[] cleartext1 = aesCipher.doFinal(encryptedText);
	    String decryptedText = new String(cleartext1);
	    System.err.println("Client: "+ decryptedText);
	    
	    
	    Scanner sc = new Scanner(System.in);
		String txt = sc.nextLine();
		
		
		SecretKey key = generateKey();
		byte[] encodedKey = encryptKey(key);
		byte[] cipherText = encryptMessage(txt,key);
		
		
		client.sendMessageClientEncrypted(encodedKey, cipherText);

	}
	
	public void sendMessageServerIntegrity(String txt, byte[] macKey, byte[] macData) throws NoSuchAlgorithmException, InvalidKeyException, RemoteException{
		SecretKeySpec spec = new SecretKeySpec(macKey, "HmacMD5");
		Mac mac = Mac.getInstance("HmacMd5");
		
		mac.init(spec);
		mac.update(txt.getBytes());
		
		byte [] macCode = mac.doFinal();
		
		if (macCode.length != macData.length){
			System.out.println("ERROR: Integrity check failed, possible intercept");
		} else if (!Arrays.equals(macCode, macData)){
			System.out.println ("ERROR: Integrity check failed, possible intercept");
		} else {
			System.out.println("Client: " + txt);
		}
		
		
	    Scanner sc = new Scanner(System.in);
		String toSend = sc.nextLine();
		
		generateMACKey();
		client.sendMessageClientIntegrity(toSend, macKeyBytes, generateMACData(toSend));
		
	}
	
	public void sendMessageServerEncryptedIntegrity(byte[] encryptedKey, byte[] encryptedText, byte[] macKey, byte[] macData) throws RemoteException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		/* First decrypt the text to plaintext */
		Cipher aesCipher = Cipher.getInstance("AES");
	    
	    SecretKey originalKey = decryptKey(encryptedKey);
		
		aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
		// Decrypt the ciphertext
	    byte[] cleartext1 = aesCipher.doFinal(encryptedText);
	    String decryptedText = new String(cleartext1);

	    /*Integrity check the decrypted text */
	    SecretKeySpec spec = new SecretKeySpec(macKey, "HmacMD5");
		Mac mac = Mac.getInstance("HmacMd5");
		
		mac.init(spec);
		mac.update(decryptedText.getBytes());
		
		byte [] macCode = mac.doFinal();
		
		if (macCode.length != macData.length){
			System.out.println("ERROR: Integrity check failed, possible intercept");
		} else if (!Arrays.equals(macCode, macData)){
			System.out.println ("ERROR: Integrity check failed, possible intercept");
		} else {
			System.out.println("Client: " + decryptedText);
		}
		
		Scanner sc = new Scanner(System.in);
		String toSend = sc.nextLine();
		
		SecretKey key = generateKey();
		byte[] encodedKey = encryptKey(key);
		byte[] cipherText = encryptMessage(toSend,key);
		
		generateMACKey();
		
		client.sendMessageClientEncryptedIntegrity(encodedKey, cipherText, macKeyBytes, generateMACData(toSend));
	}
	
	public PublicKey getPublicKey() throws RemoteException{
		return publicKey;
	}
	
	
	public int authenticateClient(String usr, String pswd) throws RemoteException{
		if (usr.equals("seng360client") && pswd.equals("12345")){
			return 1;
		} else {
			return 0;
		}
	}
	
	public void registerClient(RMIClientInterface client) throws RemoteException {
		ServerOperation.client = client;
		clientPublicKey = ServerOperation.client.getPublicKey(); 
	}
	
	public boolean isConfidentialitySet() throws RemoteException{
		return confidentiality;
	}
	
	public boolean isIntegritySet() throws RemoteException{
		return integrity;
	}
	
	public boolean isAuthenticationSet() throws RemoteException{
		return authentication;
	}
	
	public static void main(String[] args){
		for (int i=0; i < args.length; i++){
			if (args[i].equals("c")){
				confidentiality = true;
				System.out.println("Confidentiality Set");
			} else if (args[i].equals("i")){
				integrity = true;
				System.out.println("Integrity Set");
			} else if (args[i].equals("a")){
				authentication = true;
				System.out.println("Authentication Set");
			}
		}
		
		try {
			Naming.rebind("//localhost/MyServer", new ServerOperation());
			if (authentication){
				int authenticate = 0;
				int tries = 0;
				while (authenticate != 1){
					String usr = JOptionPane.showInputDialog("Enter Username:");
					String pswd = JOptionPane.showInputDialog("Enter Password:");
					authenticate = 1;
					tries++;
					if (tries > 3){
						System.out.println("Too many incorrect tries... Exiting");
						System.exit(0);
					}
				}
			}
            System.err.println("Server ready");
            generateKeys();
            
            
        } catch (Exception e) {
        	System.err.println("Server exception: " + e.toString());
          e.printStackTrace();
        }
		
		
	}


	private SecretKey decryptKey(byte[] encryptedKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		decrypt.init(Cipher.PRIVATE_KEY, privateKey);
		byte[] decodedKey = decrypt.doFinal(encryptedKey);
		String decoded = new String (decodedKey);
		byte[] originalKey = Base64.getDecoder().decode(decoded);
		SecretKey decryptedKey = new SecretKeySpec(originalKey, 0, originalKey.length, "AES");
		return decryptedKey;
	}
	
	public static byte[] encryptKey(SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		String ciphertext = Base64.getEncoder().encodeToString(key.getEncoded());
		Cipher encryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		encryption.init(Cipher.PUBLIC_KEY, clientPublicKey);
		byte[] encryptedKey = encryption.doFinal(ciphertext.getBytes());
		return encryptedKey;
	}	
	
	private static SecretKey generateKey() throws NoSuchAlgorithmException{
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(128);
	    SecretKey aesKey = keygen.generateKey();
	    return aesKey;
	}
	
	private static byte[] encryptMessage(String text, SecretKey aesKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
	    
	    Cipher aesCipher = Cipher.getInstance("AES");
	    
	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

	    // Our cleartext
	    byte[] cleartext = text.getBytes();

	    // Encrypt the cleartext
	    byte[] ciphertext = aesCipher.doFinal(cleartext);
	    return ciphertext;
	}
	
	private static void generateKeys() throws NoSuchAlgorithmException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		
		KeyPair pair = keyGen.generateKeyPair();
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
	}
	
	/* MAC FUNCTIONS */
	private static void generateMACKey() throws NoSuchAlgorithmException{
		KeyGenerator keygen = KeyGenerator.getInstance("HmacMD5");
		SecretKey macKeyGen = keygen.generateKey();
		macKey = macKeyGen;
		byte[] keyBytes = macKey.getEncoded();
		macKeyBytes = keyBytes;
	}
	
	private static byte[] generateMACData(String txt) throws NoSuchAlgorithmException, InvalidKeyException{
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(macKey);
		mac.update(txt.getBytes());
		byte[] macData = mac.doFinal();
		mac.reset();
		return macData;
	}

}
