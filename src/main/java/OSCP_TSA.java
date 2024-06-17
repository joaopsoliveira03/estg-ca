import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

public class OSCP_TSA {
  private static final String KEYSTORE_TYPE = "Windows-MY";
  private static final String KEYSTORE_ALIAS = "<KEYSTORE_ALIAS>";
  private static final String OCSP_URL = "http://ocsp.ecee.gov.pt/publico/ocsp";
  private static final String TSA_URL = "http://freetsa.org/tsr";

  public static void main(String[] args) {
    try {
      // Open the Windows-MY Keystore
      KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
      keystore.load(null, null);

      // Get the certificate from the keystore
      X509Certificate certificate = (X509Certificate) keystore.getCertificate(KEYSTORE_ALIAS);

      // Get the certificate ID
      CertificateID certificateID = new CertificateID(
        new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
        new JcaX509CertificateHolder(certificate),
        certificate.getSerialNumber()
      );

      // Build the OCSP request
      OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
      ocspReqBuilder.addRequest(certificateID);
      OCSPReq ocspReq = ocspReqBuilder.build();

      // Send the OCSP request to the server
      URL url = new URL(OCSP_URL);
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/ocsp-request");
      connection.setRequestProperty("Accept", "application/ocsp-response");
      connection.setDoOutput(true);
      connection.getOutputStream().write(ocspReq.getEncoded());
      connection.connect();

      // Get the response from the server
      OCSPResp ocspResponse = new OCSPResp(connection.getInputStream());
      int status = ocspResponse.getStatus();

      // If the check is successful, apply the timestamp
      if (status == OCSPResp.SUCCESSFUL) {
        System.out.println("O certificado é válido de acordo com o serviço OCSP.");

        // Calculate the hash of the signed data
        byte[] hash = MessageDigest.getInstance("SHA-512").digest(ocspResponse.getEncoded());

        // Generate the timestamp request
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA512, hash);

        // Send the timestamp request to the server
        url = new URL(TSA_URL);
        connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.setRequestProperty("Accept", "application/timestamp-reply");
        connection.setDoOutput(true);
        connection.getOutputStream().write(timeStampRequest.getEncoded());
        connection.connect();

        // Read the timestamp response
        InputStream inputStream = connection.getInputStream();
        ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream);
        ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
        TimeStampResp timeStampResp = TimeStampResp.getInstance(asn1Sequence);

        // Check the timestamp response status
        if (timeStampResp.getStatus().getStatus().intValue() != PKIStatus.GRANTED) {
          throw new Exception("Falha ao obter o timestamp: " + timeStampResp.getStatus().getStatusString());
        }

        // Write the timestamp request to a file
        File file = new File("./file.tsq");
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(timeStampRequest.getEncoded());
        fileOutputStream.close();

        // Write the timestamp response to a file
        file = new File("./file.tsr");
        fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(timeStampResp.getEncoded());
        fileOutputStream.close();

        System.out.println("Timestamp aplicado com sucesso.");
      } else {
        System.out.println("O certificado não é válido de acordo com o serviço OCSP.");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
