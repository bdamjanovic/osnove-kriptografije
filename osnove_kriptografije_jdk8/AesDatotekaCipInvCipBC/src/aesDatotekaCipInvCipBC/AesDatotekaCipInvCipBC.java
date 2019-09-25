package aesDatotekaCipInvCipBC;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AesDatotekaCipInvCipBC {
	// morate importovati datoteku 	bcprov-jdk15on-162
	// desni klik na korijen projekta, Properties-Java Build Path-Add External Jars 	

    public static void sifrujDesifruj(String ulaznaDat, String izlaznaDat, 
    		int ENCDEC_MODE) throws Exception{
        byte[] kljuc = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        int bufflen = 2048;
        byte inBuff[] = new byte[bufflen];
        byte outBuff[] = new byte[bufflen];
        int ocitao = 0;
        FileInputStream fis = new FileInputStream(ulaznaDat);
        FileOutputStream fos = new FileOutputStream(izlaznaDat);
        SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", 
                                           "BC");
        cipher.init(ENCDEC_MODE, skeySpec);
        while ((ocitao = fis.read(inBuff)) != -1) {
            int processed = cipher.update(inBuff, 0, ocitao, outBuff);
            fos.write(outBuff, 0, processed);
        }
        int count = cipher.doFinal(outBuff, 0);
        System.out.println("Rezultat rada se nalazi se u datoteci " + 
                            izlaznaDat);
        fos.write(outBuff, 0, count);
        fis.close();
        fos.flush();
        fos.close();
    }
    public static void main(String[] args) throws Exception {
    	Security.addProvider( new BouncyCastleProvider() );
        sifrujDesifruj("d:/otvoreni.txt", "d:/sifrat.txt", 
                       Cipher.ENCRYPT_MODE);
        sifrujDesifruj("d:/sifrat.txt", "d:/izlaz_desif.txt", 
                       Cipher.DECRYPT_MODE);
    } 
}
