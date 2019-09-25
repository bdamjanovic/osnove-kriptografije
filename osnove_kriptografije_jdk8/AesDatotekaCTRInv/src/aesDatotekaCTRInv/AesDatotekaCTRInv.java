package aesDatotekaCTRInv;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesDatotekaCTRInv {

public static void main(String[] args) throws Exception{
    byte[] kljuc = new byte[]{
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, 
            (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, 
            (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, 
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, 
            
            (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, 
            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, 
            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, 
            (byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f
        };
        byte[] iv = new byte[]{
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
            (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
            (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f
        };   
                    
        IvParameterSpec ivParamSpec;
        int bufflen = 16384;
        
        byte inBuff[] = new byte[bufflen];
        byte outBuff[] = new byte[bufflen];
        int ocitao = 0;
        // vrijednost 2147483647 (Integer.MAX_VALUE)
        // znaci da su ispravno instalirane
        // datoteke JCE Unlimited Strength Jurisdiction Policy 
        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println(maxKeyLen);

        
        FileInputStream fis = new FileInputStream("d:/sifrat.txt");
        FileOutputStream fos = new FileOutputStream("d:/izlaz_desif.txt");

        SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "AES");
        ivParamSpec = new IvParameterSpec(iv);    
        
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        // Mogli bi da koristimo i dopunu, ali bi rezultat bio par bajta duzi
        // Cipher cipher = Cipher.getInstance("AES/CTR/PKCS7Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParamSpec);
        
        while ((ocitao = fis.read(inBuff)) != -1) {
            int processed = cipher.update(inBuff, 0, ocitao, outBuff);
            fos.write(outBuff, 0, processed);
        }
        int count = cipher.doFinal(outBuff, 0);
        System.out.println("Rezultat sifrovanja nalazi se u datoteci izlaz_desif.txt");
        fos.write(outBuff, 0, count);
        fis.close();
        fos.flush();
        fos.close();
}
}
