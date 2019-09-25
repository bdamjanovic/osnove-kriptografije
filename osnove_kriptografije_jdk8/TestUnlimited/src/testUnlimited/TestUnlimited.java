package testUnlimited;
import java.security.NoSuchAlgorithmException;
// program testira da li je potrebna instalacija
// Unlimited Strength Jurisdiction Policy Files
import javax.crypto.Cipher;
public class TestUnlimited {
	public static void main(String[] args) throws NoSuchAlgorithmException {
        boolean unlimited
	        = Cipher.getMaxAllowedKeyLength("RC5") >= 256;
	    System.out.println("Neogranicene duzne kljuceva: " + unlimited);
	}
}
