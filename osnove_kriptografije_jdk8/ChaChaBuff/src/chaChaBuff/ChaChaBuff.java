package chaChaBuff;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class ChaChaBuff {
	
public static void main(String[] args) throws Exception {
	// Za novije verzije Java JDK, morate importovati datoteku 	jaxb-api-2.3.1.jar
	// desni klik na korijen projekta, Properties-Java Build Path-Add External Jars   
	
       int bufflen = 64;
       byte inBuff[] = new byte[]{91, 92, 93, 94};
       byte outBuff[] = new byte[bufflen];
       byte invCipOutBuff[] = new byte[bufflen];
       // obavezno - 256 bita ili 32 bajta kljuc
       byte[] kljuc = DatatypeConverter.parseHexBinary(
    		   "0000000000000000000000000000000000000000000000000000000000000000");
       // obavezno - 12 bajta IV
       byte[] iv = DatatypeConverter.parseHexBinary(
    		   "000000000000000000000000");
       IvParameterSpec ivParamSpec;      
       SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "ChaCha20");
       ivParamSpec = new IvParameterSpec(iv);  
       
       Cipher cipher = Cipher.getInstance("ChaCha20");
       cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParamSpec);
       int obradjeno = cipher.update(inBuff, 0, inBuff.length, outBuff);
       cipher.doFinal(inBuff);
       
       System.out.println("Rezultat sifrovanja " + obradjeno + " bajta je ");
       System.out.println(Arrays.toString(outBuff));
        
       Cipher invCipher = Cipher.getInstance("ChaCha20");
       invCipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParamSpec);
       int obradjeno2 = invCipher.update(outBuff, 0, obradjeno, invCipOutBuff);
       invCipher.doFinal(outBuff);
       
       System.out.println("Rezultat desifrovanja " + obradjeno2 +" bajta je ");
       System.out.println(Arrays.toString(invCipOutBuff)); 
}
}








