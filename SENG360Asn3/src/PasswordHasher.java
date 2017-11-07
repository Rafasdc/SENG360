import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;



public class PasswordHasher {
	
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		String toHash = new String();
		if (args.length == 0 || args.length > 1){
			System.exit(0);
		} else {
			toHash = args[0];
		}
		System.out.println(toHash);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		sha.reset();
		byte[] bytes = sha.digest(toHash.getBytes("UTF-8"));
		
		String hashed = Base64.getEncoder().encodeToString(bytes);
		
		System.out.println(hashed);
		
	}

}
