import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class UnencryptBruteforce {
  public static void main(String[] args) throws Exception {
    // Read the encrypted file into a byte array
    FileInputStream fis = new FileInputStream("2023-CA-TP_C1_2_v01_Grupo07.enc");
    byte[] encryptedData = new byte[fis.available()];
    fis.read(encryptedData);
    fis.close();

    // Define the possible values for the encryption parameters
    String[] algorithms = {"AES", "DES"};
    String[] modes = {"CBC", "ECB"};
    String[] paddings = {"NoPadding", "PKCS5Padding"};
    boolean[] ivs = {true, false};

    // Try all possible combinations of encryption parameters
    for (String algorithm : algorithms) {
      int ivLength = algorithm.equals("AES") ? 16 : 8;
      for (String mode : modes) {
        for (String padding : paddings) {
          for (boolean iv : ivs) {
            // Create the decryption cipher with the current algorithm, mode, and padding
            SecretKeySpec keySpec = new SecretKeySpec("ESTG-LSIRC-CA-UnencryptBruteforce-2-2023!".getBytes(StandardCharsets.UTF_8), algorithm);
            Cipher cipher;
            try {
              if (iv) {
                IvParameterSpec ivSpec = new IvParameterSpec(new byte[ivLength]);
                cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
              } else {
                cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
              }
            } catch (Exception e) {
              continue;
            }

            // Attempt to decrypt the byte array of the encrypted file with the current parameters
            try {
              byte[] decryptedData = cipher.doFinal(encryptedData);
              // Write the decrypted data to a file
              FileOutputStream fos = new FileOutputStream("decrypted_" + algorithm + "_" + mode + "_" + padding + "_" + (iv ? "IV" : "NoIV") + ".pdf");
              fos.write(decryptedData);
              fos.close();
              System.out.println("Decryption successful: " + algorithm + ", " + mode + ", " + padding + ", " + (iv ? "IV" : "NoIV"));
            } catch (Exception e) {
              // Decryption failed with the current parameters
              System.out.println("Decryption failed: " + algorithm + ", " + mode + ", " + padding + ", " + (iv ? "IV" : "NoIV"));
            }
          }
        }
      }
    }
  }
}
