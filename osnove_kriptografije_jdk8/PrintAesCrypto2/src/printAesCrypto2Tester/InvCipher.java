package printAesCrypto2Tester;

public class InvCipher {
	public int Nb;
	
	
//********************************************************************************************************************************		
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
	 * InvMixColumns<p>
	 * InvMixColumns transformation takes column by column from AES State and performs matrix multiplication as follows:<br>
	 *.........| 0e 0b 0d 09 |<br>
	 *new =....| 09 0e 0b 0d | * old_column<br>
	 *.........| 0d 09 0e 0b |<br>
	 *.........| 0b 0d 09 0e |<br>
	*/
	public void InvMixColumns() {
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
	public void InvShiftRows() {
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
	
	
	/**
	 * SubBytes<p>
	 * Apply AES Inverse S-Box to every byte of State.
	 * 
	 */
	public void SubBytes() {
		// Nb is always 4 (by FIPS-197), but they live the space to change something in the future
		for (int i = 0; i <= Nb - 1; i++) {
			for (int j = 0; j <= Nb - 1; j++) {
				Data.State[i][j] = Data.InvSBox[Data.State[i][j]];
			}
		}
	}	
	
	
}
