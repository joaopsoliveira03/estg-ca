import org.bouncycastle.asn1.cms.TimeStampAndCRL;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class PrivateKeyAccess {
  public static void main(String[] args) {
    try {
      // Open the Windows-MY keystore
      KeyStore keystore = KeyStore.getInstance("Windows-MY");
      keystore.load(null, null);

      // List the aliases of the keystore
      System.out.println("Aliases: ");
      keystore.aliases().asIterator().forEachRemaining(alias -> {
        System.out.println("Alias: " + alias);
      });

      // Set the alias and password to access the private key
      String alias = "<Alias>";
      char[] password = "".toCharArray();

      PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password);

      System.out.println("Private key: " + privateKey.toString());
    } catch (UnrecoverableKeyException e) {
      System.out.println("UnrecoverableKeyException: " + e.getMessage());
    } catch (CertificateException e) {
      System.out.println("CertificateException: " + e.getMessage());
    } catch (KeyStoreException e) {
      System.out.println("KeyStoreException: " + e.getMessage());
    } catch (IOException e) {
      System.out.println("IOException: " + e.getMessage());
    } catch (NoSuchAlgorithmException e) {
      System.out.println("NoSuchAlgorithmException: " + e.getMessage());
    }
  }
}
