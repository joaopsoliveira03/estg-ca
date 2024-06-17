import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;

public class SymmetricEncryption {

  private String algorithm;
  private String mode;
  private String padding;
  private Key key;
  private IvParameterSpec iv;

  public SymmetricEncryption(String algorithm, String mode, String padding, int keySize)
      throws NoSuchAlgorithmException {
    this.algorithm = algorithm;
    this.mode = mode;
    this.padding = padding;
    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
    keyGenerator.init(keySize);
    key = keyGenerator.generateKey();
    iv = null;
  }

  public SymmetricEncryption(String algorithm, String mode, String padding, int keySize, byte[] iv)
      throws NoSuchAlgorithmException {
    this(algorithm, mode, padding, keySize);
    this.iv = new IvParameterSpec(iv);
  }

  public SymmetricEncryption(String algorithm, String mode, String padding, byte[] keyData) {
    this.algorithm = algorithm;
    this.mode = mode;
    this.padding = padding;
    key = new SecretKeySpec(keyData, algorithm);
  }

  public byte[] getKeyData() {
    return key.getEncoded();
  }

  public void saveKeyToFile(String filename) throws IOException {
    FileOutputStream fos = new FileOutputStream(filename);
    fos.write(key.getEncoded());
    fos.close();
  }

  public void loadKeyFromFile(String filename) throws IOException {
    FileInputStream fis = new FileInputStream(filename);
    byte[] keyData = new byte[fis.available()];
    fis.read(keyData);
    fis.close();
    key = new SecretKeySpec(keyData, algorithm);
  }

  public byte[] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
    if (mode.equals("CBC") || mode.equals("CFB") || mode.equals("OFB")) {
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, key);
    }
    return cipher.doFinal(plaintext);
  }

  public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
    if (mode.equals("CBC") || mode.equals("CFB") || mode.equals("OFB")) {
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
    } else {
      cipher.init(Cipher.DECRYPT_MODE, key);
    }
    return cipher.doFinal(ciphertext);
  }

  public static void main(String[] args) {
    try {
      SymmetricEncryption se = new SymmetricEncryption("AES", "ECB", "PKCS5Padding", 256);

      byte[] plaintext = "Hello world!".getBytes();
      byte[] ciphertext, decrypted;

      ciphertext = se.encrypt(plaintext);
      System.out.println("Ciphertext: " + new String(ciphertext));

      decrypted = se.decrypt(ciphertext);
      System.out.println("Plaintext: " + new String(decrypted));

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException
             | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }

    try {
      byte[] iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
      SymmetricEncryption se = new SymmetricEncryption("AES", "CFB", "PKCS5Padding", 256, iv);

      byte[] plaintext = "Hello world!".getBytes();
      byte[] ciphertext, decrypted;

      ciphertext = se.encrypt(plaintext);
      System.out.println("Ciphertext: " + new String(ciphertext));

      decrypted = se.decrypt(ciphertext);
      System.out.println("Plaintext: " + new String(decrypted));

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException
             | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }
}
