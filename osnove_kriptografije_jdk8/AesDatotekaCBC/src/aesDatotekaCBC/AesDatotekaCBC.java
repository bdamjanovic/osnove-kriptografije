package aesDatotekaCBC;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesDatotekaCBC {
	
    public static void main(String[] args) throws Exception {
        byte[] kljuc = new byte[]{
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, 
            (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, 
            (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, 
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f
        };
        byte[] iv = new byte[]{
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
            (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
            (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f
        };        
        IvParameterSpec ivParamSpec;
        int bufflen = 2048;
        byte inBuff[] = new byte[bufflen];
        byte outBuff[] = new byte[bufflen];
        
        SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "AES");
        // IV je potreban. Ako ga ne zadamo, klasa CIpher 
        // ce kreirati IV popunjen nulama.
        ivParamSpec = new IvParameterSpec(iv);
        int ocitao = 0;
        FileInputStream fis = new FileInputStream("d:/otvoreni.txt");
        FileOutputStream fos = new FileOutputStream("d:/sifrat.txt");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParamSpec);
        while ((ocitao = fis.read(inBuff)) != -1) {
            int processed = cipher.update(inBuff, 0, ocitao, outBuff);
            fos.write(outBuff, 0, processed);
        }
        int count = cipher.doFinal(outBuff, 0);
        System.out.println("Rezultat sifrovanja nalazi se u datoteci izlaz.txt");
        fos.write(outBuff, 0, count);
        fis.close();
        fos.flush();
        fos.close();        
        
        
        byte invInBuff[] = new byte[bufflen];
        byte invOutBuff[] = new byte[bufflen];
        ocitao = 0;
        count = 0;
        FileInputStream invfis = new FileInputStream("d:/sifrat.txt");
        FileOutputStream invfos = new FileOutputStream("d:/izlaz_desif.txt");
        Cipher invcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        invcipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParamSpec);
        while ((ocitao = invfis.read(invInBuff)) != -1) {
            int processed = invcipher.update(invInBuff, 0, ocitao, invOutBuff);
            invfos.write(invOutBuff, 0, processed);
        }
        count = invcipher.doFinal(invOutBuff, 0);
        System.out.println("Rezultat desifrovanja nalazi se u datoteci izlaz_desif.txt");
        invfos.write(invOutBuff, 0, count);
        invfis.close();
        invfos.flush();
        invfos.close();        

    }
}
