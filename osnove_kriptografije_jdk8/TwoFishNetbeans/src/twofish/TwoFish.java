package twofish;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class TwoFish {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
       int bufflen = 64;
       byte inBuff[] = new byte[]{91, 92, 93, 94};
       byte outBuff[] = new byte[bufflen];
       byte invCipOutBuff[] = new byte[bufflen];
       byte[] kljuc = DatatypeConverter.parseHexBinary(
    		   "00000000000000000000000000000000");
       // encrypt
       SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "Twofish/ECB/PKCS7Padding");
       Cipher cipher = Cipher.getInstance("Twofish");
       cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
       int obradjeno = cipher.doFinal(inBuff, 0, inBuff.length, outBuff);
       System.out.println("Rezultat sifrovanja (obradjeno je " + obradjeno + " bajta) je ");
       System.out.println(Arrays.toString(outBuff));
       // decrypt
       Cipher invCipher = Cipher.getInstance("Twofish");
       invCipher.init(Cipher.DECRYPT_MODE, skeySpec);
       int obradjeno2 = invCipher.doFinal(outBuff, 0, obradjeno, invCipOutBuff);
       System.out.println("Rezultat desifrovanja (obradjeno je " + obradjeno2 +" bajta) je ");
       System.out.println(Arrays.toString(invCipOutBuff)); 

    }
    
}
