import java.io.*;
import java.util.Scanner;

/**
 * The {@code Main} is a main class which process input arguments,
 * load mode (encryption/decryption) and key, read data from the file
 * and encrypted/decrypted data save to another file.
 */
public class Main {

    public static BufferedInputStream bis = null;       // for reading bytes in encryption
    public static BufferedOutputStream bos = null;      // for writing bytes in decryption
    public static BufferedReader br = null;             // for reading lines in decryption
    public static PrintWriter pw = null;                // for writing lines in encryption
    public static Scanner sc = new Scanner(System.in);

    private static boolean encryption = true; // true = encryption, false = decryption
    private static String key;  // encryption/decryption key
    private static File inputFile = null;
    private static File outputFile = null;
    private static AdvancedEncryptionStandard aes;

    /** The main launching procedure of the program.
     * @param args name of the input and output files
     */
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Too few arguments!\nArguments: [input filename] [output filename]");
            return;
        }

        loadMode(); // choose between encryption and decryption
        loadKey();  // load a key
        aes = new AdvancedEncryptionStandard(key);

        try {
            inputFile = new File(args[0]);
            outputFile = new File(args[1]);

            if (encryption)
                encryptPlaintext();
            else
                decryptCiphertext();
        }
        catch (FileNotFoundException e1) {
            System.out.println("File not found.");
        }
        catch (IOException e2) {
            System.out.println("Occured some problems while reading/writing file.");
        }
        finally {
            try {
                if (bis != null)
                    bis.close();
                if (bos != null)
                    bos.close();
                if (br != null)
                    br.close();
                if (pw != null)
                    pw.close();
            }
            catch (IOException e3) {
                System.out.println("Problems while closing file.");
            }
        }
    }

    /** Let the user choose a mode, encryption or decryption. */
    public static void loadMode() {
        System.out.println("Choose a mode:\n\te = encryption\n\td = decryption");
        String mode;
        while ((mode = sc.nextLine()).matches("[^ed]")) {
            System.out.println("Incorrect mode.");
            System.out.println("\te = encryption\n\td = decryption");
        }
        if (mode.equals("d"))
            encryption = false;
    }

    /** Let the user enter a key. */
    public static void loadKey() {
        System.out.print("Key (16 characters): ");
        while ((key = sc.nextLine()).length() != 16) {
            System.out.println("Key length has to be 16 characters.");
            System.out.print("Key (16 characters): ");
        }
    }

    /** Read a plaintext (input file) byte by byte
     * and after each 16 bytes calls method encrypt.
     * Encryption data block writes into output file.
     *
     * @throws IOException exception during reading/writing file
     */
    public static void encryptPlaintext() throws IOException {
        bis = new BufferedInputStream(new FileInputStream(inputFile));
        pw = new PrintWriter(outputFile);
        int[] datablock = new int[16];
        int index = 0;

        // read file byte by byte and after each 16 bytes encrypt datablock
        for (int i = 0; i < inputFile.length(); i++) {
            datablock[index++] = bis.read();
            if (index == 16) {  // if data block is full, then encrypt
                pw.println(aes.encrypt(datablock));
                index = 0;
            }
        }
        // if missing some bytes to 16, then fill the rest by zeros
        while (index < 16) {
            datablock[index++] = 0;
        }
        // write encryption data to the output file
        pw.println(aes.encrypt(datablock));
    }

    /** Read a ciphertext (input file) line by line,
     * parse it to the array of hexadecimal numbers,
     * convert them into decimal format and calls
     * method decrypt. Decryption data write into output file.
     *
     * @throws IOException exception during reading/writing file
     */
    public static void decryptCiphertext() throws IOException {
        br = new BufferedReader(new FileReader(inputFile));
        bos = new BufferedOutputStream(new FileOutputStream(outputFile));
        int[] datablock = new int[16];
        String[] hexnumbers; // bytes in hexadecimal form
        String line;

        while ((line = br.readLine()) != null) {
            hexnumbers = line.split(" ");
            for (int i = 0; i < hexnumbers.length; i++) {
                datablock[i] = Integer.parseInt(hexnumbers[i], 16); // convert HEX -> DEC
            }
            // write decrypted data to the output file
            bos.write(aes.decrypt(datablock));
        }
    }
}
