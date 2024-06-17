import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class AssymetricEncryption {
  private String algorithm;
  private String mode;
  private String padding;
  private Key publicKey, privateKey;

  public AssymetricEncryption(String algorithm, String mode, String padding, int keySize)
      throws NoSuchAlgorithmException {
    this.algorithm = algorithm;
    this.mode = mode;
    this.padding = padding;
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    this.publicKey = keyPair.getPublic();
    this.privateKey = keyPair.getPrivate();
  }

  public byte[] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(plaintext);
  }

  public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return cipher.doFinal(ciphertext);
  }

  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException,
    IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    AssymetricEncryption assymetricEncryption = new AssymetricEncryption("RSA", "ECB", "PKCS1Padding", 4096);
    byte[] plaintext = "Hello World!".getBytes();
    System.out.println(new String(plaintext));
    byte[] ciphertext = assymetricEncryption.encrypt(plaintext);
    System.out.println(new String(ciphertext));
    byte[] decrypted = assymetricEncryption.decrypt(ciphertext);
    System.out.println(new String(decrypted));
  }
}
