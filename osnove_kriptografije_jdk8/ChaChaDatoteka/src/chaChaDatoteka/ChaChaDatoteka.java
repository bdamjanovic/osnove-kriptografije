package chaChaDatoteka;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ChaChaDatoteka {

public static void main(String[] args) throws Exception {
	// Za novije verzije Java JDK, morate importovati datoteke 	
	// jaxb-api-2.3.1.jar i bcprov-jdk15on-162.jar
	// desni klik na korijen projekta, Properties-Java Build Path-Add External Jars 
	Security.addProvider( new BouncyCastleProvider() );
	
    byte[] kljuc = DatatypeConverter.parseHexBinary(
    		"00000000000000000000000000000000");
    byte[] iv = DatatypeConverter.parseHexBinary(
    		"0000000000000000");
                    
    IvParameterSpec ivParamSpec;
    int bufflen = 16000;
    
    byte inBuff[] = new byte[bufflen];
    byte outBuff[] = new byte[bufflen];
    int ocitao = 0;

    FileInputStream fis = new FileInputStream("d:/otvoreni.txt");
    FileOutputStream fos = new FileOutputStream("d:/sifrat.txt");
    

    SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "ChaCha");
    ivParamSpec = new IvParameterSpec(iv);    
    Cipher cipher = Cipher.getInstance("ChaCha", "BC");
    
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParamSpec);
    
    
    while ((ocitao = fis.read(inBuff)) != -1) {
        int processed = cipher.update(inBuff, 0, ocitao, outBuff);
        fos.write(outBuff, 0, processed);
    }
    int count = cipher.doFinal(outBuff, 0);
    System.out.println("Rezultat sifrovanja nalazi se u datoteci sifrat.txt");
    fos.write(outBuff, 0, count);
    fis.close();
    fos.flush();
    fos.close();
}
}
