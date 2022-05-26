package bo.sin.testfirma;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FirmadorTest {

    @Test
    public void getInstance() {
    }

    @Test
    public void firmarDsig() {
    }

    @Test
    public void leerXML() {
    }

    @Test
    public void getPrivateKey() {
    }

    @Test
    public void getPrivateKeyFromString() {
    }

    @Test
    public void getPublicKey() {
    }

    @Test
    public void getPublicKeyFromString() {
    }

    @Test
    public void getX509Certificate() {
    }

    @Test
    public void firmarXML() throws URISyntaxException, ParserConfigurationException, XMLSecurityException, org.xml.sax.SAXException {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<facturaElectronicaCompraVenta> " +
                "AQUI VA LA FACTURA XML " +
                "</facturaElectronicaCompraVenta>";
        byte[] datos = xml.getBytes(StandardCharsets.UTF_8);
        try {
            String path = new File(Firmador.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
            PrivateKey privateKey = Firmador.getPrivateKey(path + "/private_key.pem");
            X509Certificate cert =  Firmador.getX509Certificate(path + "/cert.crt");
            byte[] xmlFirmado = Firmador.firmarDsig(datos, privateKey, cert);
            String respuesta = new String(xmlFirmado);
            System.out.println("facturaFirmada: "+respuesta);
        } catch (IOException | GeneralSecurityException ex) {
            Logger.getLogger(FirmadorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}