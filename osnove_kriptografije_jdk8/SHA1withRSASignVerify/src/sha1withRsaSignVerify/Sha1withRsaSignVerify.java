package sha1withRsaSignVerify;


public class Sha1withRsaSignVerify {

	/*
	 * 
	 */
	public static void main(String[] args) throws Exception {
		
		Keys keys;
		System.out.println("Pocinje kreiranje kljuceva:");
		keys = new Keys(1024);
		keys.createKeys();
		
		System.out.println(keys.getPublicKey().getAlgorithm());
		System.out.println(keys.getPublicKey().getFormat());
		System.out.println(keys.getPublicKey().getEncoded());
		System.out.println("*****************************");
		keys.writeToFile("Datoteke/publicKey", keys.getPublicKey().getEncoded());
		
		System.out.println(keys.getPrivateKey().getAlgorithm());
		System.out.println(keys.getPrivateKey().getFormat());
		System.out.println(keys.getPrivateKey().getEncoded());
		System.out.println("*****************************");
		keys.writeToFile("Datoteke/privateKey", keys.getPrivateKey().getEncoded());

		String data = "Extreme Ways - Moby (The Bourne Identity)";
		
		System.out.println("\nPocinje kreiranje potpisa:");
		SignM sign = new SignM(data, "Datoteke/privateKey");
		sign.writeToFile("Datoteke/SignedData.txt");
		// verifikacija
		System.out.println("\nPocinje verifikacija poruke:");
		VerifyM verifyM = new VerifyM("Datoteke/SignedData.txt", "Datoteke/publicKey");
		
	}

}
