import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;

public class Sign {
  public static void main(String[] args) {
    if (args.length != 1) {
      System.out.println("Usage: Sign filepath");
    } else
      try {

        /* Gerar key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(1024, random);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        // Criar Objeto de Assinatura e inicializá-lo com a respetiva chave

        Signature xsa = Signature.getInstance("SHA1withRSA");

        xsa.initSign(priv);

        // Ler dados originais e carregá-los no objeto de assinatura

        FileInputStream fis = new FileInputStream(args[0]);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
          len = bufin.read(buffer);
          xsa.update(buffer, 0, len);
        }

        bufin.close();

        // apos ler todos os dados, gera-se a assinatura
        byte[] realSig = xsa.sign();

        // Guardar a assinatura em ficheiro
        FileOutputStream sigfos = new FileOutputStream("sig");
        sigfos.write(realSig);

        sigfos.close();

        // Guardar a chave publica em ficheiro para validacao posterior
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("suepk");
        keyfos.write(key);

        keyfos.close();

        System.out.println("Chave publica exportada (suepk):\n" + new String(key));
        System.out.println("\n\nAssinatura criada (sig):\n" + new String(realSig));

      } catch (Exception e) {
        System.err.println("Excepção: " + e);
      }
  }
}
