package keyGenerator1;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class KeyGenerator1 {

	public static void main(String[] args) throws NoSuchAlgorithmException {
	      // Kreiranje KeyGenerator objekta
	      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	      // Inicijalizacija KeyGenerator-a na 256 bita
	      keyGen.init(256);
	      // Kreiranje kljuca
	      SecretKey key = keyGen.generateKey();
	      String encodedKey =  
                Base64.getEncoder().encodeToString(key.getEncoded());
	      System.out.println(encodedKey);      
	}
} 
