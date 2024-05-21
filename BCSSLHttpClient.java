package marcos2250.sslclient;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JOptionPane;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Single-class Authenticated HTTPS/SSL Java 1.6+ client with BouncyCastle TLSv1.2 Provider.
 * Supports Windows keystore or PFX-file A1 Certificates.
 * 
 * @author marcos2250
 */
public class BCSSLHttpClient {
  
    private static final String UTF_8 = "UTF-8";
    private static final char[] EMPTY_PWD = new char[] {};
    
    // put here your connection constants
    private static final String PROXY_SERVER = "";
    private static final int PROXY_PORT = 8080;
    private static final String PROXY_LOGIN = ""; // user:password
    private static final String PFX_FILE = ""; // "k1.pfx";
    private static final String PFX_PASSWORD = "123456";

    /*
     * Usage example
     */
    public static void main(String[] args) throws Exception {
        // uncomment to debug SSL handshake
        // System.setProperty("javax.net.debug", "ssl,handshake");

        BCSSLHttpClient httpsClient = new BCSSLHttpClient();

        // can use any JSON or SOAP-envelope payload
        String payload = "{\"samplePayload\": \"1\"}";

        // HTTP header parameters
        Map<String, String> headerParameters = new HashMap<String, String>();
        headerParameters.put("accept", "application/octet-stream");
        headerParameters.put("Content-Type", "application/json");

        String url = "https://sampleserver.com/api/v1/baseService/endpoint";

        System.out.println(url);
        System.out.println(payload);
        System.out.println(headerParameters);

        // POST method (also has a GET method)
        String response = httpsClient.post(url, payload, headerParameters);
        System.out.println(response);
    }

    private SSLSocketFactory sslSocketFactory;
    private BouncyCastleProvider provider;
    private BouncyCastleJsseProvider jsseProvider;

    public BCSSLHttpClient() throws Exception {
        // initialize BC providers
        if (provider == null) {
            initializeBcProvider();
        } else {
            try {
                provider = (BouncyCastleProvider) Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
                jsseProvider = (BouncyCastleJsseProvider) Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
            } catch (Exception e) {
                initializeBcProvider();
            }
        }
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", jsseProvider);        
        SecureRandom secureRandom = SecureRandom.getInstance("DEFAULT", provider);

        KeyStore keyStore = initClientKeyStore();
        kmf.init(keyStore, EMPTY_PWD);
                
        TrustManager[] trustAnyCerts = initTrustStore();
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2", jsseProvider);
        sslContext.init(kmf.getKeyManagers(), trustAnyCerts, secureRandom);
        sslSocketFactory = sslContext.getSocketFactory();
    }
    
    private void initializeBcProvider(){
        provider = new BouncyCastleProvider();
        // have to chain both BC providers,  so it doesn't conflict with JVM's default
        jsseProvider = new BouncyCastleJsseProvider(provider);        
        // put BC providers in runtime context
        Security.addProvider(provider);
        Security.addProvider(jsseProvider);
    }
    
    private KeyStore initClientKeyStore() throws Exception {
        Key keyEntry = null;
        KeyStore keyStore;
        char[] clientPassword;

        if (!PFX_FILE.isEmpty()) {
            clientPassword = PFX_PASSWORD.toCharArray();
            // PFX A1 File
            keyStore = KeyStore.getInstance("PKCS12");
            try {
                FileInputStream fileInputStream = new FileInputStream(PFX_FILE);
                keyStore.load(fileInputStream, clientPassword);
            } catch (FileNotFoundException e) {
                throw new IllegalArgumentException("File not found!", e);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid file or incorrect password!", e);
            }

        } else {
            clientPassword = new char[] {};
            // using Windows keystore (includes A3 USB Token and others)
            try {
                keyStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
                keyStore.load(null, null);
            } catch (Exception e) {
                throw new KeyStoreException("Cannot open Windows key store!", e);
            }
        }

        // list certificate aliases
        String alias = null;
        Enumeration<String> aliases = keyStore.aliases();
        List<String> aliasesList = new ArrayList<String>();
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            aliasesList.add(alias);
        }

        // ask user to select, if it have any more keys
        if (aliasesList.size() == 1) {
            alias = aliasesList.get(0);
        } else if (aliasesList.size() > 1) {
            alias = (String) JOptionPane.showInputDialog(null, "Select your key", "Keys", //
                    JOptionPane.PLAIN_MESSAGE, null, aliasesList.toArray(), "");
            if (alias == null) {
                throw new IllegalArgumentException("Cancel.");
            }
        } else {
            throw new IllegalArgumentException("Invalid key!");
        }

        // try to pick that key
        keyEntry = keyStore.getKey(alias, clientPassword);
        if (keyEntry == null || !PrivateKey.class.isInstance(keyEntry)) {
            throw new IllegalArgumentException("Incorrect password or invalid key!");
        }

        // convert key entry into a "BKS" keystore 
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);
        Certificate[] newCertificateChain = new Certificate[certificateChain.length]; 
        for (int i = 0; i < certificateChain.length; i++) {
            byte[] encoded = certificateChain[i].getEncoded();                    
            InputStream inStream = new ByteArrayInputStream(encoded);
            newCertificateChain[i] = CertificateFactory.getInstance("X509", provider).generateCertificate(inStream);
            inStream.close();                    
        }

        PrivateKey newKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(keyEntry.getEncoded()));
        
        KeyStore bksKeyStore = KeyStore.getInstance("BKS", provider);
        bksKeyStore.load(null, null);
        bksKeyStore.setKeyEntry(alias, newKey, EMPTY_PWD, newCertificateChain);
        return bksKeyStore;
    }
       
    /**
     * Create a trust manager that does not validate certificate chains
     */
    protected TrustManager[] initTrustStore() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }
        } };
        return trustAllCerts;
    }

    private HttpURLConnection openConnection(String method, String fullUrl, Map<String, String> parameters) //
            throws Exception, MalformedURLException, IOException, ProtocolException {

        URLConnection openConnection;

        if (PROXY_SERVER.isEmpty()) {
            URL url = new URL(fullUrl);
            openConnection = url.openConnection();
        } else {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_SERVER, PROXY_PORT));
            URLStreamHandler handler;
            if (fullUrl.startsWith("https")) {
                handler = new sun.net.www.protocol.https.Handler(PROXY_SERVER, PROXY_PORT);
            } else {
                handler = new sun.net.www.protocol.http.Handler(PROXY_SERVER, PROXY_PORT);
            }

            URL url = new URL(null, fullUrl, handler);
            openConnection = url.openConnection(proxy);

            // Java 6 and 7
            String auth = new String(DatatypeConverter.printBase64Binary(new String(PROXY_LOGIN).getBytes()));
            // Java 8 onwards
            // String auth = new String(Base64.getEncoder().encode(new String(PROXY_LOGIN).getBytes()));
            auth = "Basic " + auth;
            openConnection.setRequestProperty("Proxy-Connection", "Keep-Alive");
            openConnection.setRequestProperty("Proxy-Authorization", auth);
        }

        HttpURLConnection connection = HttpURLConnection.class.cast(openConnection);
        if (fullUrl.startsWith("https")) {
            HttpsURLConnection httpsURLConnection = HttpsURLConnection.class.cast(connection);
            httpsURLConnection.setSSLSocketFactory(sslSocketFactory);
        }

        connection.setDoOutput(true);
        connection.setRequestMethod(method);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        if (parameters != null) {
            for (Entry<String, String> entry : parameters.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }
        return connection;
    }

    private void writePayload(String postArgs, HttpURLConnection connection) //
            throws IOException, UnsupportedEncodingException {
        OutputStream outputStream = connection.getOutputStream();

        BufferedOutputStream out = new BufferedOutputStream(outputStream);
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, UTF_8));

        writer.append(postArgs);

        writer.flush();
        writer.close();
        out.close();
        outputStream.close();
    }

    private String closeConnection(HttpURLConnection connection) //
            throws IOException, Exception, UnsupportedEncodingException {
        InputStream returnStream;
        int responseCode = connection.getResponseCode();
        if (responseCode >= 400) {
            returnStream = connection.getErrorStream();
        } else {
            returnStream = connection.getInputStream();
        }

        String resposta = "";
        if (returnStream != null) {
            byte[] byteArray = inputStreamToByteArray(returnStream);
            resposta = new String(byteArray, UTF_8);
            returnStream.close();
        }

        connection.disconnect();
        return resposta;
    }

    public static byte[] inputStreamToByteArray(InputStream is) throws Exception {
        BufferedInputStream bis = new BufferedInputStream(is);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int result = bis.read();
        while (result != -1) {
            buf.write((byte) result);
            result = bis.read();
        }
        byte[] bytes = buf.toByteArray();
        buf.flush();
        buf.close();
        bis.close();
        return bytes;
    }

    /**
     * GET
     */
    public String get(String urlServico, Map<String, String> parameters) throws Exception {
        HttpURLConnection connection = openConnection("GET", urlServico, parameters);
        Thread.sleep(500);
        return closeConnection(connection);
    }

    /**
     * POST
     */
    public String post(String url, String body, Map<String, String> parameters) throws Exception {
        HttpURLConnection connection = openConnection("POST", url, parameters);
        Thread.sleep(500);
        writePayload(body, connection);
        Thread.sleep(500);
        return closeConnection(connection);
    }

}
