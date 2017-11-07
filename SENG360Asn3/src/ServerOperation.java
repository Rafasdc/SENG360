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

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;


public class ServerOperation extends UnicastRemoteObject implements RMIInterface{
	private static final long serialVersionUID = 1L;
	private volatile static RMIClientInterface client;
	private static PrivateKey privateKey;
	public static PublicKey publicKey;
	private boolean clientConnected;

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
	@Override
	public String sendMessageServerEncrypted(byte[] encryptedKey, byte[] encryptedText) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
	    Cipher aesCipher = Cipher.getInstance("AES");
	    
	    SecretKey originalKey = decryptKey(encryptedKey);
		
		aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
		// Decrypt the ciphertext
	    byte[] cleartext1 = aesCipher.doFinal(encryptedText);
	    String decryptedText = new String(cleartext1);
	    
		System.err.println("receiving secret message : "+ decryptedText);
		
		return "Server says hello";
	}
	
	public String sendMessageServerIntegrity(String txt, byte[] macKey, byte[] macData) throws NoSuchAlgorithmException, InvalidKeyException, RemoteException{
		SecretKeySpec spec = new SecretKeySpec(macKey, "HmacMD5");
		Mac mac = Mac.getInstance("HmacMd5");
		
		mac.init(spec);
		mac.update(txt.getBytes());
		
		byte [] macCode = mac.doFinal();
		
		if (macCode.length != macData.length){
			return ("ERROR: Integrity check failed, possible intercept");
		} else if (!Arrays.equals(macCode, macData)){
			return ("ERROR: Integrity check failed, possible intercept");
		}
		System.out.println(Arrays.equals(macCode, macData));
		return ("They match");
		
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
	/*
	public void registerClient(RMIClientInterface client) throws RemoteException {
		this.client = client;
	}
	*/
	
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
