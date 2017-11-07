import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.*;
import javax.swing.JOptionPane;

public class ClientOperation extends UnicastRemoteObject implements RMIClientInterface{
	
	protected ClientOperation() throws RemoteException {
		super();
	}
	

	private static RMIInterface look_up;
	static PublicKey serverPublicKey;
	static SecretKey macKey;
	static byte[] macKeyBytes;
	
	public static byte[] encryptKey(SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		String ciphertext = Base64.getEncoder().encodeToString(key.getEncoded());
		Cipher encryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		encryption.init(Cipher.PUBLIC_KEY, serverPublicKey);
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

	private static void generateMACKey() throws NoSuchAlgorithmException{
		KeyGenerator keygen = KeyGenerator.getInstance("HmacMD5");
		SecretKey macKeyGen = keygen.generateKey();
		macKey = macKeyGen;
		byte[] keyBytes = macKey.getEncoded();
		macKeyBytes = keyBytes;
	}
	
	public static byte[] generateMACData(String txt) throws NoSuchAlgorithmException, InvalidKeyException{
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(macKey);
		mac.update(txt.getBytes());
		byte[] macData = mac.doFinal();
		mac.reset();
		return macData;
		
		
	}
	
	@Override
	public String sendMessageClient(String txt) throws RemoteException {
		System.out.println("Server requested something");
		return null;
	}
	
	
	public static void main(String[] args) throws MalformedURLException, RemoteException, NotBoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		
		//Naming.rebind("//localhost/Client", new ClientOperation());
		look_up = (RMIInterface) Naming.lookup("//localhost/MyServer");
		
		RMIClientInterface client = new ClientOperation();
		
		look_up.registerClient(client);
		
		
		serverPublicKey = look_up.getPublicKey();
		
		int authenticate = 0;
		while (authenticate != 1){
			String usr = JOptionPane.showInputDialog("Enter Username:");
			String pswd = JOptionPane.showInputDialog("Enter Password:");
			authenticate = look_up.authenticateClient(usr, pswd);
		}
		
		String txt = JOptionPane.showInputDialog("What is your name?");
		//String txt = "Hello";
		
		SecretKey key = generateKey();
		byte[] encodedKey = encryptKey(key);
		byte [] ciphertext = encryptMessage(txt, key);
		generateMACKey();


		
		//byte[] encryptedKey = encryptKey(encodedKey);
		//String response = look_up.sendMessageServerEncrypted(encodedKey, ciphertext);
		String response = look_up.sendMessageServerIntegrity(txt, macKeyBytes, generateMACData(txt));
		System.out.println(response);
		//JOptionPane.showMessageDialog(null, response);
	}
	

}