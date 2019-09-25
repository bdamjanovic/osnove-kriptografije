package printAesCrypto2Tester;

public class Cipher {
	
	private static String cifre = "0123456789abcdef";
	
	public int key_index;
	
	public int key_len;
	public String init_key;
	public String inputVector;
	public String inStr;
	
	/**
	 * Nb is always 4 (by FIPS-197), but authors of AES left
	 * the space to change something in the future, 
	 * so we wiil do the same
	 */
	public int Nb;	
	
	/** 
	 * Predefined Substitution Box array for SubBytes.<br> 
	 * Two basic components of many algorithms are substitution box ( S-Box) 
	 * and permutation box ( P-Box).<br>
	 * AES uses SBox explicitly, while permutations are done implicitly.
	 */
	public static int SBox [] = {
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
	/** 
	 * Predefined Inverse Substitution Box array for InvSubBytes.<br> 
	 * Two basic components of many algorithms are substitution box ( S-Box) 
	 * and permutation box ( P-Box).<br>
	 * AES uses SBox explicitly, while permutations are done implicitly
	 */
	public static int InvSBox [] = {
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};


	/** 
	 * Predefined logarithm array for Galois multiplication.<br>
	 * generator: 0xe5 hex (229 dec)<p> 
	 * To speed up Galois multiplication, we will use well known formula:<br>
	 * log(x*y)=log(x)*log(y)<br>
	 * x*y=antilog(log(x)*log(y))<br>
	 */
	public static int ltable[] = {
			0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36,
			0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
			0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f,
			0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
			0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53,
			0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
			0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21,
			0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
			0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4,
			0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
			0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13,
			0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
			0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12,
			0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
			0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56,
			0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
			0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3,
			0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
			0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf,
			0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
			0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67,
			0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
			0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34,
			0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
			0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7,
			0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
			0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a,
			0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
			0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c,
			0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
			0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0,
			0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38 };

/* tabela eksponenata: */
	/** 
	 * Predefined exponent (antilog) array for Galois multiplication.<br>
	 * generator: 0xe5 hex (229 dec) <p>
	 * To speed up Galois multiplication, we will use well known formula:<br>
	 * log(x*y)=log(x)*log(y)<br>
	 * x*y=antilog(log(x)*log(y))<br>
	 */
	public static int atable[] = {
			0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12,
			0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
			0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a,
			0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
			0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29,
			0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
			0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d,
			0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
			0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f,
			0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
			0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85,
			0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
			0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7,
			0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
			0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d,
			0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
			0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39,
			0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
			0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd,
			0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
			0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84,
			0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
			0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2,
			0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
			0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c,
			0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
			0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c,
			0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
			0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7,
			0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
			0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6,
			0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01 };


	
	
	
	
//***********************************************************************************************************************************************	
	
	public void initializeState()
	{
		int	init_key_len = 16;
		String hex = "";
		int ulaz[] = new int[16];
		int skljuc[] = new int[32];
		if (key_len == 128) init_key_len = 16;
		if (key_len == 192) init_key_len = 24;  
		if (key_len == 256) init_key_len = 32;
		
		
		
		for (int i = 0; i <= 15; i++) {
			hex = "" + inputVector.charAt(2 * i) + inputVector.charAt(2 * i + 1);
			ulaz[i] = Integer.parseInt(hex, 16);
		}
		
		for (int i = 0; i <= 3; i++) {
			for (int j = 0; j <= 3; j++) {
				Data.State[i][j] = ulaz[4 * i + j];
			}
		}
		
  	  	for (int i = 0; i <= init_key_len-1; i++) {
  	  		hex = "" + init_key.charAt(2*i) + init_key.charAt(2*i+1);
  	  		skljuc[i] = Integer.parseInt(hex, 16);
  	  	}
  	  	
  	  initialise_and_expand_key(key_len, skljuc);
	}
	

	
	/**
	 *  initialize<p>
	 *  Task:<br>
	 *  To expand key.<br>
	 *  @param key_len - (128, 192 or 256)
	 *  @param kljuc - initial key to expand.<br> 
	 *  Input variables must satisfy following conditions:<br>
	 *  key_len=128 => length(kljuc)=16 bytes<br>
	 *  key_len=192 => length(kljuc)=24 bytes<br>
	 *  key_len=256 => length(kljuc)=32 bytes<br>
	 *  Resulting key will be stored in Data.Key variable
	 */
	public void initialise_and_expand_key(int key_len, int[] kljuc) {
		int i;
		// Nb - always 4 (by FIPS-197)
		this.Nb = 4;
		for (i = 0; i <= 239; i++)
			Data.key[i] = 0x0;
			  if (key_len == 128) {
				for (i = 0; i <= 15; i++)
					Data.key[i] = kljuc[i];
				KeyExpansion128();
			  }
			  else
			  if (key_len == 192) {
				for (i = 0; i <= 23; i++)
					Data.key[i] = kljuc[i];
				KeyExpansion192();
			  }
			  else
			  if (key_len == 256) {
				for (i = 0; i <= 31; i++)
					Data.key[i] = kljuc[i];
				KeyExpansion256();
			  }
			  
			
		    String hex = "";
		    for (int k=1; k<64; k++){
		    	hex = hex + Integer.toString((Data.key[k] & 0xff) + 0x100,
  						16 /* radix */).substring(1);
		    }
	}
	
	
	/**
	 * Galois multiplication<br>
	 * Task:<br>
	 * multiply two numbers using AES (Galois) multiplication<br>
	 * To speed up Galois multiplication, we will use well known formula:<br>
	 * log(x*y)=log(x)*log(y)<br>
	 * x*y=antilog(log(x)*log(y))<br>
	 * and already calculated subresults stored in ltable and atable<br>
	 * @param a (int/byte 0..255)
	 * @param b (int/byte 0..255)
	 * @return result of multiplication
	 */
	public int galoa_mul_tab(int a, int b) {
		int s;
		int z = 0;

		/* step 1. find numbers in logarithm table */
		/* step 2. add and calculate moduo 255 */
		s = Data.ltable[a] + Data.ltable[b];
		s %= 255;
		/* step 3. find result in exponent table */
		s = Data.atable[s];
		if(a == 0) {
			s = z;
		}
		if(b == 0) {
			s = z;
		}

		return s;
	}

	/**
	 * AES RotWord<br>
	 * Task:<br>
	 * Rotate bytes inside 4 byte word, in following manner:<br>
	 * 01 02 03 04  ----> 02 03 04 01<br>
	 * This 4-byte word is Data.tmpKey variable.
	 */
	public void RotWord() {
			int a,c;
			a = Data.tmpkey[0];
			for(c=0;c<3;c++)
				Data.tmpkey[c] = Data.tmpkey[c + 1];
			Data.tmpkey[3] = a;
			return;
	}

	/**
	 * AES RCon<br>
	 * Task:<br>
	 * Exponentiate 2 (in Galois fields) In times <br>
	 * So, Variable In must be element of Galois field (e.g. Byte, or 0..255)<br>
	 * Rcon[i] is constant array that contains values given by:<br>
	 * [x^(i-1), {00}, {00}, {00}]
	 * @return result of exponentiation
 	 */
	public int rcon(int in) {
			int c=1;
			if(in == 0)
					return 0;
			while(in != 1) {
					c = galoa_mul_tab(c,2);
					in--;
			}
			return c;
	}

	/**
	 * key_expansion_base<br>
	 * Task:<br>
	 * Apply RotWord, SBox and RCon on Data.tmpKey variable.<br>
	 * Key expansion function is slightly different for different initial key sizes.<br> 
	 * For 256 bit key, we have to use SubWord (S-Box) transformation one time more  
	 * then for expansion of 128 or 192 bit keys.<br>
	 * Common part for expanding keys of any length is separated this function.
	 * @param i - key_expansion_base counter, used in rcon() function
	 */
	public void key_expansion_base(int i) {
		int a;
		/* Rotate hi 8 bits in tmpKey */
		/*---------------------    ---------------------*/
		/*| 1d | 2c | 3a | 4f | -> | 2c | 3a | 4f | 1d |*/
		/*---------------------    ---------------------*/
		RotWord();

		/* AES S-Box on every byte of State */
		for(a = 0; a < 4; a++)
			Data.tmpkey[a] = Data.SBox[ Data.tmpkey[a] ];
		/* On hi byte, apply XOR with 2^(i-1) */
		/* word[0] = word[0] XOR RCON[i]; */
		Data.tmpkey[0] ^= rcon(i);

	}
	
	/**
	 * AES key expansion 128<p>
	 * Task:<br>
	 * To expand key to 11*16 = 176 bytes<br>
	 * We need 11 sets of 16 bytes each
	 * because AES128 have (10+1) rounds and State is always 16 bytes long
	 */
	public void KeyExpansion128() {
			/* c = 16 because first 16 bytes are user defined  */
			int c = 16;
			int i = 1;
			int a;

			while(c < 176) {
					/* Copy last 4 bytes from key to temp variable */
					for(a = 0; a < 4; a++)
						Data.tmpkey[a] = Data.key[a + c - 4];

					/* On every 4 blocks (of four bytes), do calculations with tmpKey */
					if(c % 16 == 0) {
						key_expansion_base(i);
						i++;
					}

					for(a = 0; a < 4; a++) {
						Data.key[c] = Data.key[c - 16] ^ Data.tmpkey[a];
							c++;
					}
			}
	}
	
	/**
	 * AES key expansion 192<p>
	 * Task:<br>
	 * To expand key to 13*16 = 208 bytes<br>
	 * We need 13 sets of 16 bytes each
	 * because AES192 have (12+1) rounds and State is always 16 bytes long
	 */
	public void KeyExpansion192() {
		/* c = 24 because first 24 bytes are user defined  */
		int c = 24;
		int i = 1;
		int a;

		while(c < 208) {
				/* Copy last 4 bytes from key to temp variable */
				for(a = 0; a < 4; a++)
					Data.tmpkey[a] = Data.key[a + c - 4];
				/* On every 6 blocks (of four bytes), do calculations with tmpKey */
				if(c % 24 == 0) {
					key_expansion_base(i);
					i++;
				}
				for(a = 0; a < 4; a++) {
					Data.key[c] = Data.key[c - 24] ^ Data.tmpkey[a];
						c++;
				}
		}
	}
	
	/**
	 * AES key expansion 256<p>
	 * Task:<br>
	 * To expand key to 15*16 = 240 bytes<br>
	 * We need 15 sets of 16 bytes each
	 * because AES192 have (14+1) rounds and State is always 16 bytes long
	 */
	public void KeyExpansion256() {
		/* c = 32 because first 32 bytes are user defined  */
		int c = 32;
		int i = 1;
		int a;

		while(c < 240) {
				/* Copy last 4 bytes from key to temp variable */
				for(a = 0; a < 4; a++)
					Data.tmpkey[a] = Data.key[a + c - 4];

				/* On every 8 blocks (of four bytes), do calculations with tmpKey */
				if(c % 32 == 0) {
					key_expansion_base(i);
					i++;
				}
				
				// Extra S-Box, only in 256 bit mode
				if(c % 32 == 16) {
						for(a = 0; a < 4; a++)
							Data.tmpkey[a] = Data.SBox[ Data.tmpkey[a] ];
				}

				for(a = 0; a < 4; a++) {
					Data.key[c] = Data.key[c - 32] ^ Data.tmpkey[a];
						c++;
				}
		}
	}

	
//************************************************************************************************************************************************
	
	
	/**
	 * AddRoundkey.TransformState<p>
	 * @param key_index
	 * Transfrom_state() uses key_index to XOR each of 16 State bytes with current 16 key bytes 
	*/

	public void addRoundKey() {
		  int i, j;
		  for (j=0; j <= 3; j++) {
			for (i=0; i <= 3; i++) {
				Data.State[i][j] = Data.State[i][j] ^ Data.key[key_index + 4*i + j];
			}
		}
			
	}	
	
	
	
	/**
	 * SubBytes.TransformState<p>
	 * Apply AES S-Box to every byte of State.
	 * 
	 */
	public void subBytes() {
		// Nb is always 4 (by FIPS-197), but they live the space to change something in the future
		for (int i = 0; i <= Nb - 1; i++) {
			for (int j = 0; j <= Nb - 1; j++) {
				Data.State[i][j] = Data.SBox[Data.State[i][j]];
			}
		}
	}
	
	
	
	/**
	 * ShiftRows.TransformState<p>
	 * State buffer will be transformed in following manner:<br> 
	 * <br>
	 * d4 e0 b8 1e  ---->  d4 e0 b8 1e <br>
	 * <b>27</b> bf b4 41  ----> bf b4 41 <b>27</b><br>
	 * <b>11 98</b> 5d 52  ---> 5d 52 <b>11 98</b><br>
	 * <b>ae f1 e5</b> 30  ---> 30 <b>ae f1 e5</b><br>
	 * 
	 */
	public void shiftRows() {
		  int temp1, temp2;

		  temp1 = Data.State[0][1];
		  Data.State[0][1] = Data.State[1][1];
		  Data.State[1][1] = Data.State[2][1];
		  Data.State[2][1] = Data.State[3][1];
		  Data.State[3][1] = temp1;

		  temp1 = Data.State[0][2];
		  temp2 = Data.State[1][2];
		  Data.State[0][2] = Data.State[2][2];
		  Data.State[1][2] = Data.State[3][2];
		  Data.State[2][2] = temp1;
		  Data.State[3][2] = temp2;

		  temp1 = Data.State[0][3];
		  Data.State[0][3] = Data.State[3][3];
		  Data.State[3][3] = Data.State[2][3];
		  Data.State[2][3] = Data.State[1][3];
		  Data.State[1][3] = temp1;

		  return;		
	}
	
	
	
	/**
	 * MixColumns.TransformState<p>
	 *MixColumns transformation takes column by column from AES State and performs matrix multiplication as follows:<br>
	 *.........| 02 03 01 01 |<br>
	 *new = | 01 02 03 01 | * old_column<br>
	 *.........| 01 01 02 03 |<br>
	 *.........| 03 01 01 02 |<br>
	*/
	public void mixColumns() {
	int a[] = new int [4];
	int c;

	// 02 03 01 01
	// 01 02 03 01
	// 01 01 02 03
	// 03 01 01 02

	for(c=0;c<4;c++) {
		a[c] = Data.State[0][c];
		}
	Data.State[0][0] = galoa_mul_tab(a[0],2) ^ galoa_mul_tab(a[1],3) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],1);
	Data.State[0][1] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],2) ^ galoa_mul_tab(a[2],3) ^ galoa_mul_tab(a[3],1);
	Data.State[0][2] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],2) ^ galoa_mul_tab(a[3],3);
	Data.State[0][3] = galoa_mul_tab(a[0],3) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],2);

	for(c=0;c<4;c++) {
		a[c] = Data.State[1][c];
		}
	Data.State[1][0] = galoa_mul_tab(a[0],2) ^ galoa_mul_tab(a[1],3) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],1);
	Data.State[1][1] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],2) ^ galoa_mul_tab(a[2],3) ^ galoa_mul_tab(a[3],1);
	Data.State[1][2] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],2) ^ galoa_mul_tab(a[3],3);
	Data.State[1][3] = galoa_mul_tab(a[0],3) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],2);

	for(c=0;c<4;c++) {
		a[c] = Data.State[2][c];
		}
	Data.State[2][0] = galoa_mul_tab(a[0],2) ^ galoa_mul_tab(a[1],3) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],1);
	Data.State[2][1] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],2) ^ galoa_mul_tab(a[2],3) ^ galoa_mul_tab(a[3],1);
	Data.State[2][2] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],2) ^ galoa_mul_tab(a[3],3);
	Data.State[2][3] = galoa_mul_tab(a[0],3) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],2);

	for(c=0;c<4;c++) {
		a[c] = Data.State[3][c];
		}
	Data.State[3][0] = galoa_mul_tab(a[0],2) ^ galoa_mul_tab(a[1],3) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],1);
	Data.State[3][1] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],2) ^ galoa_mul_tab(a[2],3) ^ galoa_mul_tab(a[3],1);
	Data.State[3][2] = galoa_mul_tab(a[0],1) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],2) ^ galoa_mul_tab(a[3],3);
	Data.State[3][3] = galoa_mul_tab(a[0],3) ^ galoa_mul_tab(a[1],1) ^ galoa_mul_tab(a[2],1) ^ galoa_mul_tab(a[3],2);

	}
	
	
	
    /** -----------------------------------------------------------------------
     * Za ulazni niz bajta "nizBajta" duzine "duzina", vraca string 
     * u heksadekadnoj notaciji.
     *
     * @param nizBajta podaci koje treba pretvoriti.
     * @param duzina broj bajta u bloku koji treba pretvoriti.
     * @return String koji predstavlja podatke u heksadekadnoj notaciji.
     */
	public String byteArrToHexStr(byte[] nizBajta, int duzina) {
	    StringBuffer string = new StringBuffer();
	    for (int i = 0; i != duzina; i++) {
	        int v = nizBajta[i];
	        v = nizBajta[i] & 0xff;
	        string.append(cifre.charAt(v >> 4));
	        string.append(cifre.charAt(v & 0xf));
	    }
	    return string.toString();
	}

    /**
     * Za ulazni niz bajta "nizBajta" vraca string u heksadekadnoj notaciji.
     * Racuna duzinu, pa poziva ranije definisanu metodu 
     * toHex(byte[] nizBajta, int duzina) 
     * @param nizBajta podaci koje treba pretvoriti.
     * @return String koji predstavlja podatke u heksadekadnoj notaciji.
     */
	public String byteArrToHexStr(byte[] nizBajta) {
	    int duzina = nizBajta.length;
	    return byteArrToHexStr(nizBajta, duzina);
	}
	
	public String toHex(int v) {
		StringBuffer string = new StringBuffer();
        string.append(cifre.charAt(v >> 4));
        string.append(cifre.charAt(v & 0xf));
	    return string.toString();
    }
	

	/*
	 * 
     * @param duzina_kljuca - key length
     * @param  print_fips - to print results of transformations for every round similar to FIPS197 
     */
	public void encrypt(int duzina_kljuca, boolean print_fips) {
		int Nb;
		int Nr;
		int i, j;
		int runda;
		int runda2;



		switch (duzina_kljuca)
		{
			case 128 :
			{
					  Nb = 4;  // num.of cols / br.kolona
					  Nr = 10; // num.of rounds / br.rundi
					  break;
			}
			case 192 :
			{
					  Nb = 4;
					  Nr = 12;
					  break;
			}
			case 256 :
			{
					  Nb = 4;
					  Nr = 14;
					  break;
			}
			default  :
			{
					  System.out.println("Key length must be 128, 192 or 256");
					  return;
			}
		}

		if (print_fips) {
			printState();
			System.out.println("-------------");
		}

		runda2 = runda = 0;

		//*************************************
		key_index = 0;
		addRoundKey();

		for (runda = 1; runda <= Nr-1; runda++)
		{
			// SubBytes
			for (i = 0; i <= Nb-1; i++) {
				for (j = 0; j <= Nb-1; j++) {
					Data.State[i][j] = Data.SBox[ Data.State[i][j] ];
				}
			}
			shiftRows();
			mixColumns();
			key_index = 4*runda*Nb;
			addRoundKey();
			runda2=runda;
			if (print_fips) {
				printState();
				System.out.println("-------------");
			}
		}

		runda2++;
		// SubBytes
		for (i = 0; i <= Nb-1; i++) {
			for (j = 0; j <= Nb-1; j++) {
				Data.State[i][j] = Data.SBox[ Data.State[i][j] ];
			}
		}
		// Final round
		shiftRows();
		key_index = 4*runda2*Nb;
		addRoundKey();
		for (i = 0; i <= 3; i++) {
			for (j = 0; j <= 3; j++) {
				Data.Output[i][j] = Data.State[i][j];
			}
		}
		Data.byte_counter += 16;
		if (print_fips) {
			printState();
			System.out.println("-------------");
		}
		printStateAsLine();

	}


	void printState() {
		for (int i = 0; i<4; i++) {
			for(int j = 0; j<4; j++) {
				System.out.print( toHex(Data.State[j][i]) + " ");
			}
		System.out.println("");
		}
	}
	
	void printStateAsLine() {
		for (int i = 0; i<4; i++) {
			for(int j = 0; j<4; j++) {
				System.out.print( toHex(Data.State[i][j]) + " ");
			}
		}
	}
	
	
	
	
//*****************************************************************************************************************************************

	/**
	 * InvMixColumns<p>
	 * InvMixColumns transformation takes column by column from AES State and performs matrix multiplication as follows:<br>
	 *.........| 0e 0b 0d 09 |<br>
	 *new =....| 09 0e 0b 0d | * old_column<br>
	 *.........| 0d 09 0e 0b |<br>
	 *.........| 0b 0d 09 0e |<br>
	*/
	public void invMixColumns() {
		int a[] = new int[4];
		int c;

		// 0e 0b 0d 09
		// 09 0e 0b 0d
		// 0d 09 0e 0b
		// 0b 0d 09 0e

		for(c=0;c<4;c++) {
			a[c] = Data.State[0][c];
			}
		Data.State[0][0] = galoa_mul_tab(a[0],0x0e) ^ galoa_mul_tab(a[1],0x0b) ^ galoa_mul_tab(a[2],0x0d) ^ galoa_mul_tab(a[3],0x09);
		Data.State[0][1] = galoa_mul_tab(a[0],0x09) ^ galoa_mul_tab(a[1],0x0e) ^ galoa_mul_tab(a[2],0x0b) ^ galoa_mul_tab(a[3],0x0d);
		Data.State[0][2] = galoa_mul_tab(a[0],0x0d) ^ galoa_mul_tab(a[1],0x09) ^ galoa_mul_tab(a[2],0x0e) ^ galoa_mul_tab(a[3],0x0b);
		Data.State[0][3] = galoa_mul_tab(a[0],0x0b) ^ galoa_mul_tab(a[1],0x0d) ^ galoa_mul_tab(a[2],0x09) ^ galoa_mul_tab(a[3],0x0e);

		for(c=0;c<4;c++) {
			a[c] = Data.State[1][c];
			}
		Data.State[1][0] = galoa_mul_tab(a[0],0x0e) ^ galoa_mul_tab(a[1],0x0b) ^ galoa_mul_tab(a[2],0x0d) ^ galoa_mul_tab(a[3],0x09);
		Data.State[1][1] = galoa_mul_tab(a[0],0x09) ^ galoa_mul_tab(a[1],0x0e) ^ galoa_mul_tab(a[2],0x0b) ^ galoa_mul_tab(a[3],0x0d);
		Data.State[1][2] = galoa_mul_tab(a[0],0x0d) ^ galoa_mul_tab(a[1],0x09) ^ galoa_mul_tab(a[2],0x0e) ^ galoa_mul_tab(a[3],0x0b);
		Data.State[1][3] = galoa_mul_tab(a[0],0x0b) ^ galoa_mul_tab(a[1],0x0d) ^ galoa_mul_tab(a[2],0x09) ^ galoa_mul_tab(a[3],0x0e);

		for(c=0;c<4;c++) {
			a[c] = Data.State[2][c];
			}
		Data.State[2][0] = galoa_mul_tab(a[0],0x0e) ^ galoa_mul_tab(a[1],0x0b) ^ galoa_mul_tab(a[2],0x0d) ^ galoa_mul_tab(a[3],0x09);
		Data.State[2][1] = galoa_mul_tab(a[0],0x09) ^ galoa_mul_tab(a[1],0x0e) ^ galoa_mul_tab(a[2],0x0b) ^ galoa_mul_tab(a[3],0x0d);
		Data.State[2][2] = galoa_mul_tab(a[0],0x0d) ^ galoa_mul_tab(a[1],0x09) ^ galoa_mul_tab(a[2],0x0e) ^ galoa_mul_tab(a[3],0x0b);
		Data.State[2][3] = galoa_mul_tab(a[0],0x0b) ^ galoa_mul_tab(a[1],0x0d) ^ galoa_mul_tab(a[2],0x09) ^ galoa_mul_tab(a[3],0x0e);

		for(c=0;c<4;c++) {
			a[c] = Data.State[3][c];
			}
		Data.State[3][0] = galoa_mul_tab(a[0],0x0e) ^ galoa_mul_tab(a[1],0x0b) ^ galoa_mul_tab(a[2],0x0d) ^ galoa_mul_tab(a[3],0x09);
		Data.State[3][1] = galoa_mul_tab(a[0],0x09) ^ galoa_mul_tab(a[1],0x0e) ^ galoa_mul_tab(a[2],0x0b) ^ galoa_mul_tab(a[3],0x0d);
		Data.State[3][2] = galoa_mul_tab(a[0],0x0d) ^ galoa_mul_tab(a[1],0x09) ^ galoa_mul_tab(a[2],0x0e) ^ galoa_mul_tab(a[3],0x0b);
		Data.State[3][3] = galoa_mul_tab(a[0],0x0b) ^ galoa_mul_tab(a[1],0x0d) ^ galoa_mul_tab(a[2],0x09) ^ galoa_mul_tab(a[3],0x0e);

	}
	
	
	/**
	 * InvShiftRows<p>
	 * State buffer will be transformed in following manner:<br> 
	 * <br>
	 * 7A 89 2B 3D  ---->  7A 89 2B 3D <br>
	 * D5 EF CA <b>9F</b>  ----> <b>9F</b> DF EF CA<br>
	 * FD 4E <b>10 F5</b>  ---> <b>10 F5</b> FD 4E<br>
	 * A7 <b>27 0B 9F0</b>  ---> <b>27 0B 9F</b> A7<br>
	 * 
	 */
	public void invShiftRows() {
		int temp1, temp2;

		temp1 = Data.State[0][1];
		temp2 = Data.State[2][1];

		Data.State[0][1] = Data.State[3][1];
		Data.State[2][1] = Data.State[1][1];
		Data.State[1][1] = temp1;
		Data.State[3][1] = temp2;

		temp1 = Data.State[3][2];
		temp2 = Data.State[0][2];
		Data.State[0][2] = Data.State[2][2];
		Data.State[3][2] = Data.State[1][2];
		Data.State[1][2] = temp1;
		Data.State[2][2] = temp2;

		temp1 = Data.State[0][3];
		Data.State[0][3] = Data.State[1][3];
		Data.State[1][3] = Data.State[2][3];
		Data.State[2][3] = Data.State[3][3];
		Data.State[3][3] = temp1;

		return;
	}
	
	public void decrypt(int duzina_kljuca, boolean print_fips) {
	
				int Nb=4;
				int Nr=4;
				int i, j;
				int runda;
				int runda2;
				
				switch (duzina_kljuca)
				{
					case 128 :
					{
							  Nb = 4;  // num.of cols / br.kolona
							  Nr = 10; // num.of rounds / br.rundi
							  break;
					}
					case 192 :
					{
							  Nb = 4;
							  Nr = 12;
							  break;
					}
					case 256 :
					{
							  Nb = 4;
							  Nr = 14;
							  break;
					}
					default  :
					{
							  System.out.println("Key length must be 128, 192 or 256");
							  return;
					}
				}

				if (print_fips) {
					printState();
					System.out.println("-------------");
				}
				
				

				
				
				
				runda2 = 0;
				runda = 0;
				//*************************************
				key_index = 4*Nr*Nb;
				addRoundKey();
				for (runda = Nr-1; runda >= 1; runda--)
				{
					invShiftRows();
				    // invSubBytes();
					// Nb is always 4 (by FIPS-197), but they live the space to change something in the future
					for (int p = 0; p <= Nb - 1; p++) {
						for (int q = 0; q <= Nb - 1; q++) {
							Data.State[p][q] = Data.InvSBox[Data.State[p][q]];
						}
					}
					
				    key_index = 4*runda*Nb;
					addRoundKey();
					invMixColumns();
					runda2=runda;
					if (print_fips) {
						printState();
						System.out.println("-------------");
					}					
				}
				
				// Final round 
				invShiftRows();
			    // invSubBytes();
				// Nb is always 4 (by FIPS-197), but they live the space to change something in the future
				for (int p = 0; p <= Nb - 1; p++) {
					for (int q = 0; q <= Nb - 1; q++) {
						Data.State[p][q] = Data.InvSBox[Data.State[p][q]];
					}
				}
				

				key_index =  0;
				addRoundKey( );
				for (i = 0; i <= 3; i++) {
					for (j = 0; j <= 3; j++) {
						Data.Output[i][j] = Data.State[i][j];
					}
				}
				Data.byte_counter += 16;
				if (print_fips) {
					printState();
					System.out.println("-------------");
				}				
				printStateAsLine();
	}

}
