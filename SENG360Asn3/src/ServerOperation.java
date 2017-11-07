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

	protected ServerOperation() throws RemoteException {
		super();
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
		client.sendMessageClient(toSend);

		
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
	
	
	private static void generateKeys() throws NoSuchAlgorithmException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		
		KeyPair pair = keyGen.generateKeyPair();
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
	}
	/*
	public void contactClient() throws RemoteException {
		client.sendMessageClient("hello");
	}
	*/
	
	public static void main(String[] args){
		try {
			Naming.rebind("//localhost/MyServer", new ServerOperation());            
            System.err.println("Server ready");
            generateKeys();
            
        } catch (Exception e) {
        	System.err.println("Server exception: " + e.toString());
          e.printStackTrace();
        }
		
		
	}




}
