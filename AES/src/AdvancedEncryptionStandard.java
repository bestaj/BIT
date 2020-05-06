/**
 * The {@code AdvancedEncryptionStandard} class provides all operations
 * for encryption/decryption of AES cipher. {@link #encrypt(int[])} enrypt
 * a data block, {@link #decrypt(int[])} decrypt a data block.
 */
public class AdvancedEncryptionStandard {
    private static final int SIZE = 16; // size of the key/datablock
    private static final int COLUMN_SIZE = 4; // size of the column/row
    private static final int TWENTY_SEVEN = 27;
    private static final int BIT_MASK = 255; // mask to create 8bit integer
    private static final int LOWER_MASK = 15; // take only right half of the byte, mask: 00001111
    private static final int KEY_COUNT = 10; // count of expansion keys

    /** Constants for each iteration in excapnsion key, */
    private static final int[] RCON = new int[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c};
    /** S-Box for encryption */
    private static final int[][] SBOX_ENCRYPTION = new int[][] {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x1, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x4, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x5, 0x9a, 0x7, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x9, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x0, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x2, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x6, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x8},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x3, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
    /** S-Box for decryption */
    private static final int[][] SBOX_DECRYPTION = new int[][] {
            {0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x0, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45, 0x6},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x2, 0xc1, 0xaf, 0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x4, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    private int[][] keys = new int[11][16]; // 11 keys for single iteration
    private int[] data; // encryption/decryption datablock
    private int currentKey; // index of the key which is currently using
    private int[][] sbox; // using S-Box

    /**
     * Create an instance of AES and generate all expansion keys.
     *
     * @param key initial key
     */
    public AdvancedEncryptionStandard(String key) {
        generateKeys(key);
    }

    /**
     * Encrypt plaintext.
     *
     * @param datablock 16 bytes plaintext which is encrypt
     * @return  encrypted data block in hexadecimal form
     */
    public String encrypt(int[] datablock) {
        this.data = datablock;
        this.sbox = SBOX_ENCRYPTION;
        this.currentKey = 0;

        // Initial round
        addRoundKey();
        currentKey++;

        // Main rounds
        for (int i = 0; i < 9; i++) {
            subBytes();
            shiftRowsLeft();
            mixColumnsEncryption();
            addRoundKey();
            currentKey++;
        }

        // Final round
        subBytes();
        shiftRowsLeft();
        addRoundKey();

        // Convert result into hexadecimal form
        String result = "";
        for (int i = 0; i < SIZE; i++) {
            result += String.format("%02x ", data[i]);
        }
        return result;
    }

    /**
     * Decrypt ciphertext.
     *
     * @param datablock 16 bytes ciphertext which is decrypt
     * @return array of decrypted bytes
     */
    public byte[] decrypt(int[] datablock) {
        this.data = datablock;
        this.sbox = SBOX_DECRYPTION;
        this.currentKey = 10;

        // Inverse final round
        addRoundKey();
        currentKey--;
        shiftRowsRight();
        subBytes();

        // Inverse main rounds
        for (int i = 0; i < 9; i++) {
            addRoundKey();
            currentKey--;
            mixColumnsDecryption();
            shiftRowsRight();
            subBytes();
        }

        addRoundKey();

        // Convert result into array of bytes
        byte[] bytes = new byte[16];
        for (int i = 0; i < SIZE; i++) {
            bytes[i] = (byte)data[i];
        }
        return bytes;
    }

    /** Every byte in datablock is XORed with corresponding
     * byte in the key.
     */
    private void addRoundKey() {
        for (int i = 0; i < SIZE; i++) {
            data[i] ^= keys[currentKey][i];
        }
    }

    /** Make substitution of each byte in datablock
     * according to corresponding S-Box.
     * Column is got as a right half of the byte.
     * Row is got as a left half of the byte.
     * Intersection of the row and column in the S-Box
     * determines a new value.
     */
    private void subBytes() {
        int row, column;
        for (int i = 0; i < SIZE; i++) {
            column = data[i] & LOWER_MASK;  // use mask to get only right 4bits of the byte
            row = data[i] >> 4; // shift 4 right to get only left 4bits of the byte
            data[i] = sbox[row][column];
        }
    }

    /**
     * Shift rows of datablock about specific number to the left.
     * Used in the encryption.
     */
    private void shiftRowsLeft() {
        int tmp;
        // shift second row = shift 1 left
        tmp = data[1];
        data[1] = data[5];
        data[5] = data[9];
        data[9] = data[13];
        data[13] = tmp;
        // shift third row = shift 2 left
        tmp = data[2];
        data[2] = data[10];
        data[10] = tmp;
        tmp = data[6];
        data[6] = data[14];
        data[14] = tmp;
        // shift fourth row = shift 3 left = shift 1 right
        tmp = data[15];
        data[15] = data[11];
        data[11] = data[7];
        data[7] = data[3];
        data[3] = tmp;
    }

    /**
     * Shift rows of datablock about specific number to the right.
     * Used in the decryption.
     */
    private void shiftRowsRight() {
        int tmp;
        // shift second row = shift 1 right
        tmp = data[13];
        data[13] = data[9];
        data[9] = data[5];
        data[5] = data[1];
        data[1] = tmp;
        // shift third row = shift 2 right
        tmp = data[2];
        data[2] = data[10];
        data[10] = tmp;
        tmp = data[6];
        data[6] = data[14];
        data[14] = tmp;
        // shift fourth row = shift 3 right = shift 1 left
        tmp = data[3];
        data[3] = data[7];
        data[7] = data[11];
        data[11] = data[15];
        data[15] = tmp;
    }

    /**
     * Make a matrices multiplication in GF(2^8)
     * with a defined matrix for encryption.
     *  [2 3 1 1]
     *  [1 2 3 1]
     *  [1 1 2 3]
     *  [3 1 1 2]
     */
    private void mixColumnsEncryption() {
        int[] newMatrix = new int[SIZE];
        int[] x2 = new int[SIZE]; // all bytes multiply by 2
        int[] x3 = new int[SIZE]; // all bytes multiply by 3
        int a;  // temporary value

        // multiply all bytes in matrix (datablock) by 2 and 3 in Galois Field 2^8
        for (int i = 0; i < SIZE; i++) {
            // multiply by 2
            a = data[i] << 1;   // shift left
            if (data[i] > 127) {  // if original 8. bit was 1, then xor with 00011001 (27)
                a &= BIT_MASK;  // mask rest of the integer, need only 8bits
                a ^= TWENTY_SEVEN;
            }
            x2[i] = a;
            // multiply by 3
            x3[i] = x2[i] ^ data[i];
        }

        for (int i = 0; i < SIZE; i++) {
            switch (i % COLUMN_SIZE) {  // get corresponding row and use appropriate form
                case 0:
                    newMatrix[i] = x2[i] ^ x3[i+1] ^ data[i+2] ^ data[i+3];
                    break;
                case 1:
                    newMatrix[i] = data[i-1] ^ x2[i] ^ x3[i+1] ^ data[i+2];
                    break;
                case 2:
                    newMatrix[i] = data[i-2] ^ data[i-1] ^ x2[i] ^ x3[i+1];
                    break;
                case 3:
                    newMatrix[i] = x3[i-3] ^ data[i-2] ^ data[i-1] ^ x2[i];
                    break;
            }
        }
        data = newMatrix;
    }

    /**
     * Make a matrices multiplication in GF(2^8)
     * with a defined matrix for decryption.
     *  [12 11 13  9]
     *  [ 9 14 11 13]
     *  [13  9 14 11]
     *  [11 13  9 14]
     */
    private void mixColumnsDecryption() {
        int[] newMatrix = new int[SIZE];
        int[] x9 = new int[SIZE];  // all bytes multiply by 9
        int[] x11 = new int[SIZE]; // all bytes multiply by 11
        int[] x13 = new int[SIZE]; // all bytes multiply by 13
        int[] x14 = new int[SIZE]; // all bytes multiply by 14

        // multiply all bytes in matrix by 9, 11, 13 and 14 in Galois Field 2^8
        for (int i = 0; i < SIZE; i++) {
            x9[i] = GFmultiply(9, data[i]);
            x11[i] = GFmultiply(11, data[i]);
            x13[i] = GFmultiply(13, data[i]);
            x14[i] = GFmultiply(14, data[i]);
        }

        for (int i = 0; i < SIZE; i++) {
            switch (i % COLUMN_SIZE) { // get corresponding row and use appropriate form
                case 0:
                    newMatrix[i] = x14[i] ^ x11[i+1] ^ x13[i+2] ^ x9[i+3];
                    break;
                case 1:
                    newMatrix[i] = x9[i-1] ^ x14[i] ^ x11[i+1] ^ x13[i+2];
                    break;
                case 2:
                    newMatrix[i] = x13[i-2] ^ x9[i-1] ^ x14[i] ^ x11[i+1];
                    break;
                case 3:
                    newMatrix[i] = x11[i-3] ^ x13[i-2] ^ x9[i-1] ^ x14[i];
                    break;
            }
        }
        data = newMatrix;
    }

    /**
     * Multiplicate two values in Galois Field 2^8.
     * Using Russian peasant multiplication algorithm.
     *
     * @param a first value
     * @param b second value
     * @return result of multiplication
     */
    private int GFmultiply(int a, int b) {
        int p = 0;  // product of the multiplication
        while ((a != 0) && (b != 0)) {  // if a or b is 0, then stop iteration
            if ((b & 1) == 1) // if b is odd, then add a to p (addition in GF(2^m) is xor)
                p ^= a;  // add a to p, but addition in GF(2^m) is XOR
            if (a > 127)    // if a > 127 then reduce wiht polynomial x^8 + x^4 + x^3 + x + 1
                a = (a << 1) ^ 0b100011011;
            else
                a <<= 1;
            b >>= 1;
        }
        return p;
    }

    /**
     * Key expansion of all keys.
     *
     * @param key the initial key
     */
    private void generateKeys(String key) {
        int[] lastColumn = new int[COLUMN_SIZE];

        // Save an initial key
        for (int i = 0; i < key.length(); i++) {
            keys[0][i] = key.charAt(i);
        }

        int tmp, row, column;
        for (int i = 1; i <= KEY_COUNT; i++) {  // generate all other keys
            // Shift left the last column of the previous key
            tmp = keys[i-1][12];
            lastColumn[0] = keys[i-1][13];
            lastColumn[1] = keys[i-1][14];
            lastColumn[2] = keys[i-1][15];
            lastColumn[3] = tmp;

            // Substitution of the last column
            for (int j = 0; j < COLUMN_SIZE; j++) {
                column = lastColumn[j] & LOWER_MASK; // use mask to get only right 4bits of the byte
                row = lastColumn[j] >> 4; // shift 4 right to get only left 4bits of the byte
                lastColumn[j] = SBOX_ENCRYPTION[row][column];
            }

            // XOR of the round constant for the current iteration and the leftmost byte of the last column
            lastColumn[0] ^= RCON[i-1];

            // XOR with the first column of the previous key (creating a first column of the next key)
            keys[i][0]  = keys[i-1][0] ^ lastColumn[0];
            keys[i][1]  = keys[i-1][1] ^ lastColumn[1];
            keys[i][2]  = keys[i-1][2] ^ lastColumn[2];
            keys[i][3]  = keys[i-1][3] ^ lastColumn[3];

            /* XOR with other columns, (new column) XOR (previous next column), i.e.
               second new column = first new column XOR second old column
               third new column = second new column XOR third old column
               fourth new column = third new column XOR fourth old column */
            for (int j = 4; j < 16; j++) {
                keys[i][j] = keys[i-1][j] ^ keys[i][j - COLUMN_SIZE];
            }
        }
    }
}
