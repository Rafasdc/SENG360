import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface RMIClientInterface extends Remote {

	public void sendMessageClient(String txt) throws RemoteException;
	
	public void sendMessageClientEncrypted(byte[] encryptedKey, byte[] encryptedText) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;

	public void sendMessageClientIntegrity(String txt, byte[] macKey, byte[] macData) throws NoSuchAlgorithmException, InvalidKeyException, RemoteException;
	
	public PublicKey getPublicKey() throws RemoteException;
	
	public void sendMessageClientEncryptedIntegrity(byte[] encryptedKey, byte[] encryptedText, byte[] macKey, byte[] macData) throws RemoteException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

}
