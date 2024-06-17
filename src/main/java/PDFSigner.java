import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;

public class PDFSigner {

  public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
    String keystorePath = "./joaop.p12";
    String keystorePassword = "SuperSaf3Passw@rd";
    String alias = "<Alias>";
    String pdfPath = "./2023-CA-TP_C30_v01.pdf";
    String pdfPathSigned = "./2023-CA-TP_C30_v01_signed.pdf";

    // Load the P12 certificate
    KeyStore keystore = KeyStore.getInstance("PKCS12");
    InputStream inputStream = new FileInputStream(keystorePath);
    keystore.load(inputStream, keystorePassword.toCharArray());

    // Retrieve data from the certificate
    Key key = keystore.getKey(alias, keystorePassword.toCharArray());
    PrivateKey privateKey = (PrivateKey) key;
    Certificate certificate = keystore.getCertificate(alias);

    // Load the PDF file
    PDDocument document = Loader.loadPDF(new File(pdfPath));

    // Create signature interface
    SignatureInterface signatureInterface = new SignatureInterface() {
      @Override
      public byte[] sign(InputStream content) throws IOException {
        try {
          // Create Signature object
          Signature signature = Signature.getInstance("SHA256withRSA");

          // Initialize Signature object with the private key
          signature.initSign(privateKey);

          // Read the content of the PDF and update the Signature object
          byte[] buffer = new byte[8192];
          int length;
          while ((length = content.read(buffer)) != -1) {
            signature.update(buffer, 0, length);
          }

          // Generate the signature
          byte[] signedData = signature.sign();

          return signedData;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
          e.printStackTrace();
          throw new IOException("Error occurred while signing the document.", e);
        }
      }
    };

    // Create signature
    PDSignature signature = new PDSignature();
    signature.setType(COSName.CERT);
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    signature.setName("João Oliveira");
    signature.setLocation("<Place>");
    signature.setReason("Compreendo e aceito as regras do trabalho prático e eventuais alterações pontuais que sejam introduzidas.");
    signature.setSignDate(Calendar.getInstance());

    // Create signature options
    SignatureOptions signatureOptions = new SignatureOptions();
    signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE);
    signatureOptions.setPage(document.getNumberOfPages() - 1);

    // Sign the PDF document
    document.addSignature(signature, signatureOptions);

    // Save the signed document
    document.saveIncremental(new FileOutputStream(pdfPathSigned));

    // Close the document
    document.close();
  }
}

