import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.*;
import javax.swing.JOptionPane;

public class ClientOperation {
	private static RMIInterface look_up;
	static PublicKey serverPublicKey;
	
	public static byte[] encryptKey(String ciphertext) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		Cipher encryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		encryption.init(Cipher.PUBLIC_KEY, serverPublicKey);
		byte[] encryptedKey = encryption.doFinal(ciphertext.getBytes());
		return encryptedKey;
	}

	public static void main(String[] args) throws MalformedURLException, RemoteException, NotBoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		
		
		look_up = (RMIInterface) Naming.lookup("//localhost/MyServer");
		serverPublicKey = look_up.getPublicKeyServer();
		//System.out.println(serverPublicKey);
		//String txt = JOptionPane.showInputDialog("What is your name?");
		String txt = "Hello";
		
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(128);
	    SecretKey aesKey = keygen.generateKey();
 
	    String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());
	    System.out.println(encodedKey);
	    
	    Cipher aesCipher = Cipher.getInstance("AES");
	    
	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

	    // Our cleartext
	    byte[] cleartext = "This is just an example".getBytes();

	    // Encrypt the cleartext
	    byte[] ciphertext = aesCipher.doFinal(cleartext);

	    // Initialize the same cipher for decryption
	    //aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

	    // Decrypt the ciphertext
	    //byte[] cleartext1 = aesCipher.doFinal(ciphertext);
	    
	    //String firstText = new String (cleartext);
	    
	    //System.out.println(firstText);


		
		//byte[] encryptedKey = encryptKey(encodedKey);
		String response = look_up.helloTo(txt, encryptKey(encodedKey), ciphertext);
		System.out.println(response);
		//JOptionPane.showMessageDialog(null, response);
	}
}