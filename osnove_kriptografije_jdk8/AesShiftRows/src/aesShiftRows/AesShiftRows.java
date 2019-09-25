package aesShiftRows;

/**
 * ShiftRows
 * <p>
 * 
 * ShftRows Bafer Stanje transformisemo npr. ovako Ulaz:
 * d42711aee0bf98f1b8b45de51e415230
 * 
 * d4 e0 b8 1e ----> d4 e0 b8 1e 
 * 27 bf b4 41 ----> bf b4 41 27 
 * 11 98 5d 52 ----> 5d 52 11 98 
 * ae f1 e5 30 ----> 30 ae f1 e5
 */

public class AesShiftRows {

public static int[][] State = new int[4][4];
public static String inStr;

// @param inStr String inStr –
// 32 alfanumerika hex vrijednosti (16 bajta)
public static void InitState() {
	String hex = "";
	int ulaz[] = new int[16];

	for (int i = 0; i <= 15; i++) {
		hex = "" + inStr.charAt(2 * i) + inStr.charAt(2 * i + 1);
		ulaz[i] = Integer.parseInt(hex, 16);
	}

	for (int i = 0; i <= 3; i++) {
		for (int j = 0; j <= 3; j++) {
			State[i][j] = ulaz[4 * i + j];
		}
	}

}

public static void ShiftRows() {
	int temp1, temp2;

	temp1 = State[0][1];
	State[0][1] = State[1][1];
	State[1][1] = State[2][1];
	State[2][1] = State[3][1];
	State[3][1] = temp1;

	temp1 = State[0][2];
	temp2 = State[1][2];
	State[0][2] = State[2][2];
	State[1][2] = State[3][2];
	State[2][2] = temp1;
	State[3][2] = temp2;

	temp1 = State[0][3];
	State[0][3] = State[3][3];
	State[3][3] = State[2][3];
	State[2][3] = State[1][3];
	State[1][3] = temp1;

	return;
}

public static void main(String[] args) {
	// inStr = args[0];
	inStr = "d42711aee0bf98f1b8b45de51e415230";
	InitState();
	String s = "";
	// Stanje prije transformacije
	for (int j = 0; j <= 3; j++) {
		for (int i = 0; i <= 3; i++) {
			s = s + Integer.toString((State[i][j] & 0xff) + 0x100, 
					16 /* radix */).substring(1) + " ";
		}
		System.out.println(s);
		s = "";
	}
	System.out.println();

	ShiftRows();
	for (int j = 0; j <= 3; j++) {
		for (int i = 0; i <= 3; i++) {
			s = s + Integer.toString((State[i][j] & 0xff) + 0x100, 
					16 /* radix */).substring(1) + " ";
		}
		System.out.println(s);
		s = "";
	}

}

}
