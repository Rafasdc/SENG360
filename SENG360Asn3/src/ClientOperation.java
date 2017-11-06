import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.*;
import javax.swing.JOptionPane;

public class ClientOperation {
	private static RMIInterface look_up;

	public static void main(String[] args) throws MalformedURLException, RemoteException, NotBoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
	    SecretKey aesKey = keygen.generateKey();
	    
	    Cipher aesCipher;
	    
	    // Create the cipher
	    aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    
	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

	    // Our cleartext
	    byte[] cleartext = "This is just an example".getBytes();

	    // Encrypt the cleartext
	    byte[] ciphertext = aesCipher.doFinal(cleartext);

	    // Initialize the same cipher for decryption
	    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

	    // Decrypt the ciphertext
	    
	    
	    byte[] cleartext1 = aesCipher.doFinal(ciphertext);
	    
	    String firstText = new String (cleartext);
	    
	    System.out.println(firstText);
		
		look_up = (RMIInterface) Naming.lookup("//localhost/MyServer");
		String txt = JOptionPane.showInputDialog("What is your name?");
			
		String response = look_up.helloTo(txt);
		System.out.println(response);
		//JOptionPane.showMessageDialog(null, response);
	}
}