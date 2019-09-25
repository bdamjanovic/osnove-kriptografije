package keyAgreementDhTest;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class KeyAgreementDhTest {
	/*
	 * Vrijednosti iz
	 * http://cr.openjdk.java.net/~valeriep/7044060/webrev.01/raw_files/new/src/share/classes/sun/security/provider/ParameterCache.java
     * odnosno iz 
     * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#algspec 
	 * L = 1024
	 * SEED = 8d5155894229d5e689ee01e6018a237e2cae64cd
	 * counter = 92
	 */
	public static BigInteger p1024
	        = new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523c"
	                + "ef4400c31e3f80b6512669455d402251fb593d8d58"
	                + "fabfc5f5ba30f6cb9b556cd7813b801d346ff26660"
	                + "b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c6"
	                + "1bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554"
	                + "135a169132f675f3ae2b61d72aeff22203199dd148"
	                + "01c7", 16);
	
	public static BigInteger q1024
	        = new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5",
	                16);
	public static BigInteger g1024 =
            new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa" +
                           "3aea82f9574c0b3d0782675159578ebad4594fe671" +
                           "07108180b449167123e84c281613b7cf09328cc8a6" +
                           "e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f" +
                           "0bfa213562f1fb627a01243bcca4f1bea8519089a8" +
                           "83dfe15ae59f06928b665e807b552564014c3bfecf" +
                           "492a", 16);	
		public static void main(String[] args) throws Exception{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        DHParameterSpec dhParams = new DHParameterSpec(p1024, g1024);
        
        KeyPairGenerator keyGenA = KeyPairGenerator.getInstance("DH", "BC");
        keyGenA.initialize(dhParams, new SecureRandom());
        KeyPairGenerator keyGenB = KeyPairGenerator.getInstance("DH", "BC");
        keyGenB.initialize(dhParams, new SecureRandom());

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");

        KeyPair aPair = keyGenA.generateKeyPair();
        KeyPair bPair = keyGenB.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        MessageDigest hash1 = MessageDigest.getInstance("SHA1", "BC"); 
        System.out.println("------ 160 - bitni kljuc (20 bajta)  ------");
        System.out.println(new String(hash1.digest(aKeyAgree.generateSecret())));
        System.out.println(new String(hash1.digest(bKeyAgree.generateSecret())));
        
        MessageDigest hash2 = MessageDigest.getInstance("SHA256", "BC");
        System.out.println("------ 256- bitni kljuc (32 bajta)  ------");
        System.out.println(new String(hash2.digest(aKeyAgree.generateSecret())));
        System.out.println(new String(hash2.digest(bKeyAgree.generateSecret())));
                
	}
}
