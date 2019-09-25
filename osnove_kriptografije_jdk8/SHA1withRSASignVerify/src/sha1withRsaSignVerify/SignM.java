package sha1withRsaSignVerify;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


public class SignM {
private List<byte[]> list;
	
	// Konstruktor kreira listu koja ce biti upisana u datoteku 
	// Lista se sastoji od niza bajta poruke i od niza bajta potpisa
	public SignM(String data, String keyFile) throws InvalidKeyException, Exception {
		list = new ArrayList<byte[]>();
		list.add(data.getBytes());
		list.add(sign(data, keyFile));
	}
	
	// Metod koji potpisuje podatke pomocu privatnog kljuca iz datoteke keyFile 
	public byte[] sign(String data, String keyFile) throws InvalidKeyException, Exception{
		Signature rsa = Signature.getInstance("SHA1withRSA"); 
		rsa.initSign(getPrivate(keyFile));
		rsa.update(data.getBytes());
		return rsa.sign();
	}
	
	/* Metoda ucitava privatni kljuc iz datoteke
	 * Klasa PKCS8EncodedKeySpec predstavlja nacin za enkodiranje privatnog kljuca
	 * u skladu sa ASN.1 tipom PrivateKeyInfo kako je definisano u PKCS#8 standardu
	 * PrivateKeyInfo ::= SEQUENCE {
     * version Version,
     * privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
     * privateKey PrivateKey,
     * attributes [0] IMPLICIT Attributes OPTIONAL }
	 */
	public PrivateKey getPrivate(String filename) throws Exception {
		File file = new File(filename);
		Path path = file.toPath(); 
		byte[] keyBytes = Files.readAllBytes(path);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}
	
	// Metod koji upisuje listu bajta u datoteku i na ekran
	// ObjectOutputStream upisuje objekte u tok FileOutputStream
	// Upisuju se naziv klase, njen potpis (signature) i vrijednosti polja i nizova
	public void writeToFile(String filename) throws FileNotFoundException, IOException {
		// Zapisivanje u datoteku
		File f = new File(filename);
		f.getParentFile().mkdirs();
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename));
	    out.writeObject(list);
		out.close();
		
		// Ispis na ekran
		int counter = 0;
		final Iterator<byte[]> iter = list.iterator();
		while (iter.hasNext()) {
			if (counter == 0) {
				System.out.println("Podaci (Txt + Byte)");
				System.out.println("*********************");
			}else {
				System.out.println("Potpis (Txt + Byte)");	
				System.out.println("*********************");
			}
			counter++;
			final byte[] bytes = iter.next();
			String s = new String(bytes); 
			System.out.println(s);
			for (Byte b : bytes)
				System.out.print(b + " ");
			System.out.println("");			
		}
		System.out.println("");
		System.out.println("Datoteka je spremna");
		
	}
}
