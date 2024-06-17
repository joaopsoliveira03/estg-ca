import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;

public class PDFDecrypter {
  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());

    String encryptedFilePath = "./file.enc";
    String p12FilePath = "./joaop.p12";
    String p12Password = "SuperSaf3Passw@rd";
    String alias = "<Alias>";
    String outputFilePath = "./decrypted.pdf";

    try {
      // Load the encrypted file into a byte array
      File file = new File(encryptedFilePath);
      byte[] encryptedData = new byte[(int) file.length()];
      try (FileInputStream fileInputStream = new FileInputStream(file)) {
        fileInputStream.read(encryptedData);
      }

      // Load the P12 file
      KeyStore keystore = KeyStore.getInstance("PKCS12");
      InputStream inputStream = new FileInputStream(p12FilePath);
      keystore.load(inputStream, p12Password.toCharArray());

      // Get the private key from the P12 file
      PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, p12Password.toCharArray());

      // Create a CMSEnvelopedData object from the encrypted data
      CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

      // Get the recipient information
      RecipientInformationStore recipientInfos = envelopedData.getRecipientInfos();
      RecipientInformation recipientInfo = recipientInfos.getRecipients().iterator().next();

      // Create a JceKeyTransEnvelopedRecipient object with the decrypted session key
      JceKeyTransEnvelopedRecipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
      recipient.setProvider("BC");

      // Decrypt the content
      byte[] decryptedContent = recipientInfo.getContent(recipient);

      // Write the decrypted content to a new file
      try (FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
        fileOutputStream.write(decryptedContent);
      }

      System.out.println("File decryption complete!");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
