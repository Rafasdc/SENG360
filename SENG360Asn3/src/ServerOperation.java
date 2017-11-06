import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.*;
import javax.swing.JOptionPane;


public class ServerOperation extends UnicastRemoteObject implements RMIInterface{
	private static final long serialVersionUID = 1L;
	private static PrivateKey privateKey;
	public static PublicKey publicKey;

	protected ServerOperation() throws RemoteException {
		super();
	}

	private String decryptKey(byte[] encryptedKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS5Padding");
		decrypt.init(Cipher.ENCRYPT_MODE, privateKey);
		String decryptedKey = new String(decrypt.doFinal(encryptedKey));
		return decryptedKey;
	}
	
	public String helloTo(String name, byte[] encryptedKey, byte[] encryptedText) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
	    Cipher aesCipher;
	    aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		
		aesCipher.init(Cipher.DECRYPT_MODE, key);
	    // Decrypt the ciphertext
	    byte[] cleartext1 = aesCipher.doFinal(encryptedText);
	    String decryptedText = new String(cleartext1);
	    
		System.err.println(name + " is sending secret message : "+ decryptedText);
		return "Server says hello to " + name;
	}
	
	public PublicKey getPublicKeyServer() throws RemoteException{
		return publicKey;
	}
	
	private static void generateKeys() throws NoSuchAlgorithmException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		keyGen.initialize(2048);
		
		KeyPair pair = keyGen.generateKeyPair();
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
	}
	
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
