package printAesCrypto2Tester;

public class PrintAesCrypto2Tester {
	

	
	public static void main(String[] args) {
		Cipher c = new Cipher();
		
		
		c.inputVector = "3243f6a8885a308d313198a2e0370734";
		c.init_key = "2b7e151628aed2a6abf7158809cf4f3c";
		c.key_len = 128;
		
		c.initializeState();
		
		// arg1 - keyLen:  
		// arg2 - print FIPS197-like results 
		c.encrypt(128, false);
		System.out.println();
		
		
		c.inputVector = "3925841d02dc09fbdc118597196a0b32";
		c.init_key = "2b7e151628aed2a6abf7158809cf4f3c";
		c.key_len = 128;
		
		c.initializeState();		
		c.decrypt(128, true);
		
		
		

	}

}
