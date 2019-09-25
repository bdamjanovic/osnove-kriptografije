package chaChaPoly1305;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class ChaChaPoly1305 {
    // obavezno - 256 bita ili 32 bajta kljuc
    static byte[] kljuc = DatatypeConverter.parseHexBinary(
 		   "0000000000000000000000000000000000000000000000000000000000000000");
    // obavezno - 12 bajta IV
    static  byte[] iv = DatatypeConverter.parseHexBinary(
 		   "000000000000000000000000");
    static int bufflen = 64;
    static byte inBuff[] = new byte[]{91, 92, 93, 94};
    static byte outBuff[] = new byte[bufflen];
    static byte invCipOutBuff[] = new byte[bufflen];  
    
	public static void encrypt() throws Exception
	{
	       IvParameterSpec ivParamSpec;      
	       SecretKeySpec skeySpec = new SecretKeySpec(kljuc, 
	    		   "ChaCha20");
			       // None znaci bez drugog nacina rada
			       // NoPadding - bez dopune
	       ivParamSpec = new IvParameterSpec(iv);  
	       
	       Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
	       
	       Cipher cipher1 = Cipher.getInstance("ChaCha20-Poly1305");
	       cipher1.init(Cipher.ENCRYPT_MODE, skeySpec, ivParamSpec);
	       int obradjeno = cipher1.update(inBuff, 0, 4, outBuff);
	       System.out.println("Rezultat sifrovanja " + obradjeno + " bajta je ");
	       System.out.println(Arrays.toString(outBuff));		
	}

	public static void decrypt() throws Exception
	{
	       IvParameterSpec ivParamSpec;      
	       SecretKeySpec skeySpec = new SecretKeySpec(kljuc, 
	    		   "ChaCha20-Poly1305/None/NoPadding");
			       // None znaci bez drugog nacina rada
			       // NoPadding - bez dopune
	       ivParamSpec = new IvParameterSpec(iv);  		
	       Cipher invCipher = Cipher.getInstance("ChaCha20-Poly1305");
	       invCipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParamSpec);
	       int obradjeno2 = invCipher.update(outBuff, 0, 4, invCipOutBuff);
	       invCipher.doFinal(outBuff);
	       
	       System.out.println("Rezultat desifrovanja " + obradjeno2 +" bajta je ");
	       System.out.println(Arrays.toString(invCipOutBuff));
	}
	
	public static void main(String[] args) throws Exception{
		encrypt();
		decrypt();
	}
}
