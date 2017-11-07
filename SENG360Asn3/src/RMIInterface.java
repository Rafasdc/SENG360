import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.*;

public interface RMIInterface extends Remote {

    public void sendMessageServerEncrypted(byte[] encryptedKey, byte[] encryptedText) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;

    public PublicKey getPublicKey() throws RemoteException;

	public void sendMessageServerIntegrity(String txt, byte[] macKeyBytes, byte[] generateMACData) throws RemoteException, NoSuchAlgorithmException, InvalidKeyException;

	public int authenticateClient(String usr, String pswd) throws RemoteException;
	
	public void registerClient(RMIClientInterface client) throws RemoteException;
	
	public boolean isConfidentialitySet() throws RemoteException;
	
	public boolean isIntegritySet() throws RemoteException;
	
	public boolean isAuthenticationSet() throws RemoteException;

	public void sendMessageServerEncryptedIntegrity(byte[] encryptedKey, byte[] encryptedText, byte[] macKey, byte[] macData) throws RemoteException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;
}
