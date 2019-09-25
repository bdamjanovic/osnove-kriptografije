package keyGenerator4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyGenerator4 {
	
	
	public static void  curveTest() {
	    final X9ECParameters curve = NISTNamedCurves.getByName("P-384");
	    final ECDomainParameters domainParameters = new ECDomainParameters(
	            curve.getCurve(), curve.getG(), curve.getN());
	    final SecureRandom random = new SecureRandom();
	    final ECKeyPairGenerator gen = new ECKeyPairGenerator();
	    gen.init(new ECKeyGenerationParameters(domainParameters, random));
	    final AsymmetricCipherKeyPair senderPair = gen.generateKeyPair();
	    final AsymmetricCipherKeyPair receiverPair = gen.generateKeyPair();
	    final ECDHBasicAgreement senderAgreement = new ECDHBasicAgreement();
	    senderAgreement.init(senderPair.getPrivate());
	    final BigInteger senderResult = senderAgreement.calculateAgreement(
	            receiverPair.getPublic());
	    final ECDHBasicAgreement receiverAgreement = new ECDHBasicAgreement();
	    receiverAgreement.init(receiverPair.getPrivate());
	    final BigInteger receiverResult = receiverAgreement.calculateAgreement(
	            senderPair.getPublic());
	    if (senderResult.equals(receiverResult))
	    	System.out.println("ok");
	    else
	    	System.out.println("greska");
	    		
	    		
	    //System.out.println(receiverResult);
	}	

	public static void test() throws Exception {
		System.out.println("ED25519 with BC");
		
        Security.addProvider(new BouncyCastleProvider());
        BouncyCastleProvider provider =  (BouncyCastleProvider) Security.getProvider("BC");
        System.out.println("Provider          :" + ((java.security.Provider) provider).getName() + " Version: " + ((java.security.Provider) provider).getVersion());
        // generate ed25519 keys
        SecureRandom RANDOM = new SecureRandom();
        
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(RANDOM));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        // the message
        byte[] message = "Message to sign".getBytes("utf-8");
        // create the signature
        Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();
        // verify the signature
        Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKey);
        verifier.update(message, 0, message.length);
        boolean shouldVerify = verifier.verifySignature(signature);
        // output
        byte[] privateKeyEncoded = privateKey.getEncoded();
        byte[] publicKeyEncoded = publicKey.getEncoded();
        System.out.println("privateKey Length :" + privateKeyEncoded.length + " Data:"
                + DatatypeConverter.printHexBinary(privateKeyEncoded));
        System.out.println("publicKey Length  :" + publicKeyEncoded.length + " Data:"
                + DatatypeConverter.printHexBinary(publicKeyEncoded));
        System.out.println(
                "signature Length  :" + signature.length + " Data:" + DatatypeConverter.printHexBinary(signature));
        System.out.println("signature correct :" + shouldVerify);
        // rebuild the keys
        System.out.println("Rebuild the keys and verify the signature with rebuild public key");
        Ed25519PrivateKeyParameters privateKeyRebuild = new Ed25519PrivateKeyParameters(privateKeyEncoded, 0);
        Ed25519PublicKeyParameters publicKeyRebuild = new Ed25519PublicKeyParameters(publicKeyEncoded, 0);
        byte[] privateKeyRebuildEncoded = privateKeyRebuild.getEncoded();
        System.out.println("privateKey Length :" + privateKeyRebuild.getEncoded().length + " Data:"
                + DatatypeConverter.printHexBinary(privateKeyRebuild.getEncoded()));
        byte[] publicKeyRebuildEncoded = publicKeyRebuild.getEncoded();
        System.out.println("publicKey Length  :" + publicKeyRebuild.getEncoded().length + " Data:"
                + DatatypeConverter.printHexBinary(publicKeyRebuild.getEncoded()));
        // compare the keys
        System.out.println("private Keys Equal:" + Arrays.equals(privateKeyEncoded, privateKeyRebuildEncoded));
        System.out.println("public Keys Equal :" + Arrays.equals(publicKeyEncoded, publicKeyRebuildEncoded));
        // verify the signature with rebuild public key
        Signer verifierRebuild = new Ed25519Signer();
        verifierRebuild.init(false, publicKeyRebuild);
        verifierRebuild.update(message, 0, message.length);
        boolean shouldVerifyRebuild = verifierRebuild.verifySignature(signature);
        System.out.println("signature correct :" + shouldVerifyRebuild + " with rebuild public key");
        
        
    }
	
	
	public static void main(String[] args) throws Exception {
		test();
		System.out.println("***********************************************************************");
		curveTest();
		System.out.println("***********************************************************************");

		
        // creating the object of SecureRandom 
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); 

        // Declaring the string variable 
        String str = "9"; 

        // Declaring the byte Array b 
        byte[] b = str.getBytes(); 

        // Reseeding the random object 
        sr.setSeed(b);
	      
	      
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
		keyPairGenerator.initialize(255, sr);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		
		System.out.println("Ispis generisanih kljuceva:");
		byte[] encodedKey;		
		encodedKey = publicKey.getEncoded();
		String s = DatatypeConverter.printHexBinary(encodedKey); 
		System.out.println("Javni kljuc getEncoded() "
				+ "i DatatypeConverter Heksadekadno:");
		System.out.println("--------------");
		System.out.println(s);
		
		encodedKey = privateKey.getEncoded();
		s = DatatypeConverter.printHexBinary(encodedKey); 
		System.out.println("Privatni kljuc getEncoded() "
				+ "i DatatypeConverter Heksadekadno:");
		System.out.println("--------------");
		System.out.println(s);
		
		
		
		
		
		

	}

}
