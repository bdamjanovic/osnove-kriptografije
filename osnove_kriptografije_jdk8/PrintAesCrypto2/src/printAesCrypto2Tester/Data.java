/**
 * Boris Damjanovic, 230/08, FON, Belgrade - crypto2 - 2009
 */

package printAesCrypto2Tester;

/***********************************************************************
 *  
 */  
/**
 * Data:<p>
 * This class purpose is to hold initial values, results and inter-results.
 */
public class Data {
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

/**
 * Getter for Substituton Box, for SubButes transformation.<br>
 * Two basic components of many algorithms are substitution box ( S-Box) 
 * and permutation box ( P-Box).<br>
 * AES uses SBox explicitly, while permutations are done implicitly
 * @return the sBox
 */
public int[] getSBox() {
	return SBox;
}
/**
 * @param sBox the sBox to set
 */
public void setSBox(int[] sBox) {
	SBox = sBox;
}
/**
 * Getter for Inverse Substituton Box, for InvSubButes transformation.<br>
 * Two basic components of many algorithms are substitution box ( S-Box) 
 * and permutation box ( P-Box).<br>
 * AES uses SBox explicitly, while permutations are done implicitly
 * @return the invSBox
 */
public int[] getInvSBox() {
	return InvSBox;
}
/**
 * @param invSBox the invSBox to set
 */
public void setInvSBox(int[] invSBox) {
	InvSBox = invSBox;
}
/** 
 * Getter for logarithm array for Galois multiplication<br>
 * generator: 0xe5 hex (229 dec) <p>
 * To speed up Galois multiplication, we will use well known formula:<br>
 * log(x*y)=log(x)*log(y)<br>
 * x*y=antilog(log(x)*log(y))<br>
 * @return the ltable
 */
public int[] getLtable() {
	return ltable;
}
/**
 * @param ltable the ltable to set
 */
public void setLtable(int[] _ltable) {
	ltable = _ltable;
}
/**
 * Getter for antilogarithm array for Galois multiplication.<br>
 * generator: 0xe5 hex (229 dec)<p>
 * To speed up Galois multiplication, we will use well known formula:<br>
 * log(x*y)=log(x)*log(y)<br>
 * x*y=antilog(log(x)*log(y))<br>
 * @return the atable
 */
public int[] getAtable() {
	return atable;
}
/**
 * @param atable the atable to set
 */
public void setAtable(int[] _atable) {
	atable = _atable;
}

/**
 * Bytes (or blocks) of file that already encrypted/decrypted
 * @return the byte_counter
 */
public int getByte_counter() {
	return byte_counter;
}
/**
 * @param byteCounter the byte_counter to set
 */
public void setByte_counter(int byteCounter) {
	byte_counter = byteCounter;
}
/**
 * tmpKey holds initial four bytes for keyExpansion.<br>
 * Procedure is as follows:<br>
 *  1.Get last four bytes from already generated key<br>
 *  2.Generate new 16 bytes of key<br>
 *  repeat until reach full key size
 * @return the tmpkey
 */
public int[] getTmpkey() {
	return tmpkey;
}
/**
 * @param tmpkey the tmpkey to set
 */
public void setTmpkey(int[] _tmpkey) {
	tmpkey = _tmpkey;
}
/**
 * Key array holds expanded key
 * @return the key
 */
public int[] getKey() {
	return key;
}
/**
 * @param key the key to set
 */
public void setKey(int[] _key) {
	key = _key;
}
/**
 * Input - 4x4 bytes array that hold input into Cipher/InvCipher
 * @return the input
 */
public int[][] getInput() {
	return Input;
}
/**
 * @param input the input to set
 */
public void setInput(int[][] input) {
	Input = input;
}
/**
 * Rectangular array of bytes, having 4 rows and 4 columns.
 * Holds results and inter-results of transformations.
 * @return the state
 */
public int[][] getState() {
	return State;
}
/**
 * @param state the state to set
 */
public void setState(int[][] state) {
	State = state;
}
/**
 * Output - 4x4 bytes array that hold output from Cipher/InvCipher
 * @return the output
 */
public int[][] getOutput() {
	return Output;
}
/**
 * @param output the output to set
 */
public void setOutput(int[][] output) {
	Output = output;
}
	/**
	 * Bytes (or blocks) of file that already encrypted/decrypted
	*/
	public static int byte_counter;
	
	/**
	 * tmpKey (int[4]) holds initial four bytes for keyExpansion.<br>
	 * Procedure is as follows:<br>
	 *  1.Get last four bytes from already generated key<br>
	 *  2.Generate new 16 bytes of key<br>
	 *  repeat until reach full key size
	*/
	public static int tmpkey[] = new int[4];
	
	/**
	 * Key:<p>
	 * Key array (int[240]) holds expanded key. Key expansion is done according to 
	 * following rules for initial key length.<br>
	 * InitKey128 => 10+1 rounds => 11*16 bytes<br>
	 * InitKey192 => 12+1 rounds => 13*16 bytes<br>
	 * InitKey256 => 14+1 rounds => 15*16 bytes
	 */
	public static int key[]= new int[240];

	/**
	 * Input:<p>
	 * 4x4 bytes array (int[4][4]) that hold input into Cipher/InvCipher
	 */
	public static int [][] Input = new int[4][4];
	
	/**
	 * State:<p>
	 * Rectangular array of bytes, having 4 rows and 4 columns (int[4][4]).
	 * Holds results and inter-results of transformations.
	 */
	public static int [][] State = new int[4][4];
	
	/**
	 * Output:<p>
	 * 4x4 bytes array (int[4][4]) that hold output from Cipher/InvCipher
	 */
	public static int [][] Output = new int[4][4];
	
	/**
	 * source_code_template_0:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String source_code_template_0 = 
		"// AES128 from FIPS197 pg.33-34\n"+
		"// First try test vector no.1\n"+
		"// (3243f6a8885a308d313198a2e0370734)\n"+
		"// Then try to experiment.\n"+
		"key_len = 128;\n"+
		"init_key = \"2b7e151628aed2a6abf7158809cf4f3c\";\n"+
		"keyExpansion.KeyExpansion128();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 10; //br.rundi // number of rounds\n"+
		"addRoundKey.key_index = 0;\n"+
		"addRoundKey.TransformState();\n"+
		"for (runda = 1; runda <= Nr-1; runda++)\n"+
		"{\n"+
		"	subBytes.TransformState();\n"+
		"	shiftRows.TransformState();\n"+
		"	mixColumns.TransformState();\n"+
		"   addRoundKey.key_index = 4*runda*Nb;\n"+
		"	addRoundKey.TransformState( );\n"+
		"	runda2=runda;\n"+
		"}\n"+
		"runda2++;\n"+
		"subBytes.TransformState();\n"+
		"// Final round\n"+
		"shiftRows.TransformState();\n"+
		"addRoundKey.key_index = 4*runda2*Nb;\n"+
		"addRoundKey.TransformState(  );";
	
	
	/**
	 * source_code_template_1:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String source_code_template_1 = 
		"// AES128 from FIPS197 pg.35-36\n"+
		"// First try test vector no.2\n"+
		"// (3243f6a8885a308d313198a2e0370734)\n"+
		"// Then try to experiment.\n"+
		"key_len = 128;\n"+
		"init_key = \"000102030405060708090a0b0c0d0e0f\";\n"+
		"keyExpansion.KeyExpansion128();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 10; //br.rundi // number of rounds\n"+
		"addRoundKey.key_index = 0;\n"+
		"addRoundKey.TransformState();\n"+
		"for (runda = 1; runda <= Nr-1; runda++)\n"+
		"{\n"+
		"	subBytes.TransformState();\n"+
		"	shiftRows.TransformState();\n"+
		"	mixColumns.TransformState();\n"+
		"   addRoundKey.key_index = 4*runda*Nb;\n"+
		"	addRoundKey.TransformState( );\n"+
		"	runda2=runda;\n"+
		"}\n"+
		"runda2++;\n"+
		"subBytes.TransformState();\n"+
		"// Final round\n"+
		"shiftRows.TransformState();\n"+
		"addRoundKey.key_index = 4*runda2*Nb;\n"+
		"addRoundKey.TransformState(  );";
	
	/**
	 * source_code_template_2:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String source_code_template_2 =
		"// AES192 from FIPS197 pg.38-39\n"+
		"// First, try test vector no.3\n"+
		"// (00112233445566778899aabbccddeeff)\n"+
		"// Then try to experiment.\n"+
		"key_len = 192;\n"+
		"init_key = \"000102030405060708090a0b0c0d0e0f1011121314151617\";\n"+
		"keyExpansion.KeyExpansion192();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 12; //br.rundi // number of rounds\n"+
		"addRoundKey.key_index = 0;\n"+
		"addRoundKey.TransformState();\n"+
		"for (runda = 1; runda <= Nr-1; runda++)\n"+
		"{\n"+
		"	subBytes.TransformState();\n"+
		"	shiftRows.TransformState();\n"+
		"	mixColumns.TransformState();\n"+
		"   addRoundKey.key_index = 4*runda*Nb;\n"+
		"	addRoundKey.TransformState( );\n"+
		"	runda2=runda;\n"+
		"}\n"+
		"runda2++;\n"+
		"subBytes.TransformState();\n"+
		"// Final round\n"+
		"shiftRows.TransformState();\n"+
		"addRoundKey.key_index = 4*runda2*Nb;\n"+ 
		"addRoundKey.TransformState(  );";

	/**
	 * source_code_template_3:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String source_code_template_3 =
		"// AES256 from FIPS197 pg.42\n"+
		"// First, try test vector no.4\n"+
		"// (00112233445566778899aabbccddeeff)\n"+
		"// Then try to experiment.\n"+
		"key_len = 256;\n"+
		"init_key = \"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\";\n"+
		"keyExpansion.KeyExpansion256();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 14; //br.rundi // number of rounds\n"+
		"addRoundKey.key_index = 0;\n"+
		"addRoundKey.TransformState();\n"+
		"for (runda = 1; runda <= Nr-1; runda++)\n"+
		"{\n"+
		"	subBytes.TransformState();\n"+
		"	shiftRows.TransformState();\n"+
		"	mixColumns.TransformState();\n"+
		"   addRoundKey.key_index = 4*runda*Nb;\n"+
		"	addRoundKey.TransformState( );\n"+
		"	runda2=runda;\n"+
		"}\n"+
		"runda2++;\n"+
		"subBytes.TransformState();\n"+
		"// Final round\n"+
		"shiftRows.TransformState();\n"+
		"addRoundKey.key_index = 4*runda2*Nb;\n"+
		"addRoundKey.TransformState(  );";
	

	/**
	 * inverse_source_code_template_0:<br>
	 * "Real" AES inverse cipher source code to be supplied to every registered user.<br>
	 */
	public static String inverse_source_code_template_0 = 
		"// AES128 from FIPS197 pg.33-34\n"+
		"// First try test vector no.1\n"+
		"// (3243f6a8885a308d313198a2e0370734)\n"+
		"// Then try to experiment.\n"+
		"key_len = 128;\n"+
		"init_key = \"2b7e151628aed2a6abf7158809cf4f3c\";\n"+
		"keyExpansion.KeyExpansion128();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 10; //br.rundi // number of rounds\n"+

		"addRoundKey.key_index = 4*Nr*Nb;\n" +
		"addRoundKey.TransformState();\n" +
		"for (runda = Nr-1; runda >= 1; runda--)\n" +
		"{\n" +
		"	invShiftRows.TransformState();\n" +
		"   invSubBytes.TransformState();\n" +
		"   addRoundKey.key_index = 4*runda*Nb;\n" +
		"	addRoundKey.TransformState( );\n" +
		"	invMixColumns.TransformState();\n" +
		"}\n" +
		"\n" +

		"invShiftRows.TransformState();\n" +
		"invSubBytes.TransformState();\n" +
		"// Final round\n" +
		"addRoundKey.key_index = 0;\n" +
		"addRoundKey.TransformState(  );\n";

	
	/**
	 * source_code_template_1:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String inverse_source_code_template_1 = 
		"// AES128 from FIPS197 pg.35-36\n"+
		"// First try test vector no.2\n"+
		"// (3243f6a8885a308d313198a2e0370734)\n"+
		"// Then try to experiment.\n"+
		"key_len = 128;\n"+
		"init_key = \"000102030405060708090a0b0c0d0e0f\";\n"+
		"keyExpansion.KeyExpansion128();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 10; //br.rundi // number of rounds\n"+
		
		"addRoundKey.key_index = 4*Nr*Nb;\n" +
		"addRoundKey.TransformState();\n" +
		"for (runda = Nr-1; runda >= 1; runda--)\n" +
		"{\n" +
		"	invShiftRows.TransformState();\n" +
		"   invSubBytes.TransformState();\n" +
		"   addRoundKey.key_index = 4*runda*Nb;\n" +
		"	addRoundKey.TransformState( );\n" +
		"	invMixColumns.TransformState();\n" +
		"}\n" +
		"\n" +

		"invShiftRows.TransformState();\n" +
		"invSubBytes.TransformState();\n" +
		"// Final round\n" +
		"addRoundKey.key_index = 0;\n" +
		"addRoundKey.TransformState(  );\n";
	
	/**
	 * source_code_template_2:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String inverse_source_code_template_2 =
		"// AES192 from FIPS197 pg.38-39\n"+
		"// First, try test vector no.3\n"+
		"// (00112233445566778899aabbccddeeff)\n"+
		"// Then try to experiment.\n"+
		"key_len = 192;\n"+
		"init_key = \"000102030405060708090a0b0c0d0e0f1011121314151617\";\n"+
		"keyExpansion.KeyExpansion192();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 12; //br.rundi // number of rounds\n"+

		"addRoundKey.key_index = 4*Nr*Nb;\n" +
		"addRoundKey.TransformState();\n" +
		"for (runda = Nr-1; runda >= 1; runda--)\n" +
		"{\n" +
		"	invShiftRows.TransformState();\n" +
		"   invSubBytes.TransformState();\n" +
		"   addRoundKey.key_index = 4*runda*Nb;\n" +
		"	addRoundKey.TransformState( );\n" +
		"	invMixColumns.TransformState();\n" +
		"}\n" +
		"\n" +

		"invShiftRows.TransformState();\n" +
		"invSubBytes.TransformState();\n" +
		"// Final round\n" +
		"addRoundKey.key_index = 0;\n" +
		"addRoundKey.TransformState(  );\n";

	/**
	 * source_code_template_3:<br>
	 * "Real" AES cipher source code to be supplied to every registered user.<br>
	 */
	public static String inverse_source_code_template_3 =
		"// AES256 from FIPS197 pg.42\n"+
		"// First, try test vector no.4\n"+
		"// (00112233445566778899aabbccddeeff)\n"+
		"// Then try to experiment.\n"+
		"key_len = 256;\n"+
		"init_key = \"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\";\n"+
		"keyExpansion.KeyExpansion256();\n"+ 
		"Nb = 4;  //br.kolona //number of columns\n"+
		"Nr = 14; //br.rundi // number of rounds\n"+

		"addRoundKey.key_index = 4*Nr*Nb;\n" +
		"addRoundKey.TransformState();\n" +
		"for (runda = Nr-1; runda >= 1; runda--)\n" +
		"{\n" +
		"	invShiftRows.TransformState();\n" +
		"   invSubBytes.TransformState();\n" +
		"   addRoundKey.key_index = 4*runda*Nb;\n" +
		"	addRoundKey.TransformState( );\n" +
		"	invMixColumns.TransformState();\n" +
		"}\n" +
		"\n" +

		"invShiftRows.TransformState();\n" +
		"invSubBytes.TransformState();\n" +
		"// Final round\n" +
		"addRoundKey.key_index = 0;\n" +
		"addRoundKey.TransformState(  );\n";


}
