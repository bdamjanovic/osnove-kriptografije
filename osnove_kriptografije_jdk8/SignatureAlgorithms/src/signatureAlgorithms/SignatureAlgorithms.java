package signatureAlgorithms;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SignatureAlgorithms {

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		byte[] data = "A-ha - The Living Daylights".getBytes();

		/* Generisemo i verifikujemo razlicite algoritme dig.potpisa */
		try {
			String KeyPairInstances[] = { "RSA", "RSA", 
					                      "DSA", "DSA", 
					                      "EC", "EC", "Ed25519" };
			int KeyLengths[] = { 2048, 2048, 
					             2048, 2048, 
					             571, 571, 255 };
			String SignatureInstances[] = { "SHA1withRSA", "MD5withRSA", 
					                        "SHA/DSA", "SHA1withDSA", 
					                        "SHA1withECDSA", "SHA256withECDSA", "Ed25519" };
			
			for(int i = 0; i < KeyPairInstances.length; i++) {
			// generisemo par kljuceva 
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KeyPairInstances[i]);
			keyGen.initialize(KeyLengths[i], new SecureRandom());
			KeyPair pair = keyGen.generateKeyPair();
			// kreiramo instancu klase Signature
			Signature signature = Signature.getInstance(SignatureInstances[i]);
			// Inicijaizujemo instancu privatnim kljucem 
			PrivateKey priv = pair.getPrivate();
			signature.initSign(priv);
			// ispisujemo nayiv algoritma
			System.out.println(signature.getAlgorithm());
			System.out.println(signature.toString());
			// Azuriramo dig.potpis na osnovu podataka
			signature.update(data);
			// kreiramo niz bajta kao potpis
			byte[] sig = signature.sign();

			// Verifikacija potpisa

			// Inicijaizujemo instancu javnim kljucem 
			PublicKey pub = pair.getPublic();
			Signature signature2 = Signature.getInstance(SignatureInstances[i]);
			signature2.initVerify(pub);
			// Azuriramo dig.potpis na osnovu podataka
			signature2.update(data);

			// verifikujemo pa ispisujemo poruku
			boolean verifies = signature2.verify(sig);
			if (verifies) {
				// ispisujemo nayiv provajdera
				String providerName = signature2.getProvider().getName();
				String version = Double.toString(signature2.getProvider().getVersion());
				System.out.println("Koristimo provajder " + providerName + " " + version);
				
				System.out.println(SignatureInstances[i] + "Uspjesno verifikovan "
						+ "\n--------------------\n");
			} else {
				System.out.println(SignatureInstances[i] + "Nije verifikovan");
			}
			}

		} catch (Exception e) {
			System.err.println("Caught exception " + e.toString());
		}

	}

}
