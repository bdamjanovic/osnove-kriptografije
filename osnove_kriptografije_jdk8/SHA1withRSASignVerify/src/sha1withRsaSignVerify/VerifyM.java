package sha1withRsaSignVerify;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

public class VerifyM {
	private List<byte[]> list;

	@SuppressWarnings("unchecked")
	// Konstruktor ocitava dva niza bajta iz datoteke
	// i ispisuje poruku ako je potpis verifikovan.
	// ObjectInputStream deserijalizuje objekte i podatke koji su prethodno zapisani
	// pomocu klase ObjectOutputStream
	public VerifyM(String filename, String keyFile) throws Exception {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename));
	    this.list = (List<byte[]>) in.readObject();
	    in.close();
	    boolean b = verifySignature(list.get(0), list.get(1), keyFile);
	    if (b) {
	    	System.out.println("Poruka je verifikovana"); 
	    	System.out.println("----------------");
	    	// ispisujemo prvi niz, odnosno samu poruku
	    	String s = new String(list.get(0)); 
	    	System.out.println(s); 	
	    }else {
	    	System.out.println("Poruka nije verifikovana"); 
	    }
    
	}
	
	//Method for signature verification that initializes with the Public Key, 
	//updates the data to be verified and then verifies them using the signature
	private boolean verifySignature(byte[] data, byte[] signature, String keyFile) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(getPublic(keyFile));
		sig.update(data);
		
		return sig.verify(signature);
	}
	
	//Method to retrieve the Public Key from a file
	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}
