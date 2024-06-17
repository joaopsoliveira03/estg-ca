import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Verify {
  public static void main(String[] args) {
    if (args.length != 3) {
      System.out.println("Usage: Verify validationKey signature originalData");
    } else
      try {

        // importar a chave para validacao

        FileInputStream keyfis = new FileInputStream(args[0]);
        byte[] encKey = new byte[keyfis.available()];

        keyfis.read(encKey);

        keyfis.close();

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Ler assinatura
        FileInputStream sigfis = new FileInputStream(args[1]);
        byte[] sigToVerify = new byte[sigfis.available()];
        sigfis.read(sigToVerify);
        sigfis.close();

        // Criar Objeto de Assinatura e inicializá-lo com a respetiva chave
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(pubKey);

        // Ler dados originais e carregá-los no objeto de assinatura

        FileInputStream datafis = new FileInputStream(args[2]);
        BufferedInputStream bufin = new BufferedInputStream(datafis);

        /*
         * byte[] buffer = new byte[1024];
         * int len;
         * while (bufin.available() != 0) {
         * len = bufin.read(buffer);
         * sig.update(buffer, 0, len);
         * };
         */
        sig.update(bufin.readAllBytes());

        bufin.close();

        // Validar
        System.out.println("Assinatura validada: " + sig.verify(sigToVerify));
      } catch (Exception e) {
        System.err.println("Excepcao: " + e);
      }
  }
}
