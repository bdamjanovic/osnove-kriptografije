package keyGenerator2;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class KeyGenerator2 {
	public static void main(String[] args) throws NoSuchAlgorithmException {
	      // Kreiranje KeyGenerator objekta
	      KeyGenerator keyGen = KeyGenerator.getInstance("AES");      
	      // Kreiranje SecureRandom objekta
	      SecureRandom secRandom = new SecureRandom();      
	      // Inicijalizacija KeyGenerator-a na 256 bita 
	      // uz pomoc instance SecureRandom klase
	      keyGen.init(256, secRandom);
	      // Kreiranje kljuca
	      SecretKey key = keyGen.generateKey();
	      String encodedKey = 
                Base64.getEncoder().encodeToString(key.getEncoded());
	      System.out.println(encodedKey);      
	}
}

 