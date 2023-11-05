package ipscan.model;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;

public class ScanThread extends Thread {

	private final CloseableHttpClient client;
	private List<String> ips;

	public ScanThread(CloseableHttpClient client, List<String> subList) {
		this.client = client;
		this.ips = subList;
	}

	public ScanThread(CloseableHttpClient client, String string) {
		this.client = client;
		System.out.println(string);
	}

	@Override
	public void run() {
		for (String ip : ips) {
			try (CloseableHttpResponse resp = client.execute(null)) {
				
			} catch (ClientProtocolException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private void getSSLfromIp(String uri) throws UnknownHostException, IOException, CertificateParsingException {
		URL destinationURL = new URL(uri);
		HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
		conn.connect();
		Certificate[] certs = conn.getServerCertificates();

		for (Certificate cert : certs) {
			if (cert instanceof X509Certificate) {
				X509Certificate x = (X509Certificate) cert;
				Collection<List<?>> altNames = x.getSubjectAlternativeNames();
				if (altNames != null) {
					for (List<?> altName : altNames) {
						if (altName.get(0).equals(2)) { // 2 is DNS, 7 is IP
							System.out.println("DNS Name: " + altName.get(1)); // TODO write names to file
						}
					}
				}
			} else {
				// TODO
				System.out.println(uri + " doesn't have any additional DN");
			}
		}

	}

}
