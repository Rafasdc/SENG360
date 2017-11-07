import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.*;

public interface RMIInterface extends Remote {

    public String sendMessageServerEncrypted(byte[] encryptedKey, byte[] encryptedText) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;

    public PublicKey getPublicKey() throws RemoteException;

	public String sendMessageServerIntegrity(String txt, byte[] macKeyBytes, byte[] generateMACData) throws RemoteException, NoSuchAlgorithmException, InvalidKeyException;

	public int authenticateClient(String usr, String pswd) throws RemoteException;
	
	public void registerClient(RMIClientInterface client) throws RemoteException;
}