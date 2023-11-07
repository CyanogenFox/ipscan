package ipscan.model;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import ipscan.model.utils.IpScanUtils;

public class ScanThread extends Thread {

	private final CloseableHttpClient client;
	private List<String> ips;

	public ScanThread(CloseableHttpClient client, List<String> subList) {
		this.client = client;
		this.ips = subList;
	}

	public ScanThread(CloseableHttpClient client, String string) {
		this.client = client;
	}

	@Override
	public void run() {
		int timeout = 2110;// max response time by standard (1.3 - 2.11)
		RequestConfig configRequest = RequestConfig.custom().setConnectTimeout(timeout).build();

		for (String ip : ips) {
			HttpGet request = new HttpGet("https://" + ip + "/");
			request.setConfig(configRequest);

			/**
			 * This implementation executes standard SSL verification by matching IP address
			 * with host name (or it's alternative). But it is unknown if provided IP
			 * addresses have verified (matched) host name, thus implemented functionality
			 * that ignores non matched host name with IP. TO DEVs - if it's not required
			 * for IP to be matched with host name, you can uncomment this function
			 * "noHostnameVerification(HttpRequest)". Note that is very insecure.
			 */
			try (CloseableHttpResponse response = this.client.execute(request)) {

				if (response.getStatusLine().getStatusCode() == 200) {
					getSSLfromIp(request.getURI().toString());
				}

			} catch (SSLPeerUnverifiedException e) {
				/*
				 * Uncomment this function if it's not important for SSL to be anchored with
				 * host name
				 */
//				noHostnameVerification(request);
			} catch (SSLHandshakeException | CertificateParsingException e) {
				/*
				 * Given IP don't have any SSL certification, ignore this exception to look for
				 * other IP addresses.
				 */
			} catch (ConnectTimeoutException e) {
			} catch (SSLException e) {
				System.out.println(e.getMessage());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

	@SuppressWarnings("unused")
	private void noHostnameVerification(HttpGet request) {
		// TODO change to poolclient if using this
		SSLConnectionSocketFactory scsf;
		try {
			scsf = new SSLConnectionSocketFactory(
					SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build(),
					NoopHostnameVerifier.INSTANCE);
			CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(scsf).build();

			try (CloseableHttpResponse resp = httpClient.execute(request)) {

				getSSLfromIp(request.getURI().toString());

			} catch (SSLHandshakeException | CertificateParsingException e) {
				/*
				 * Given IP don't have any SSL certification, ignore this exception to look for
				 * other IP addresses.
				 */
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
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
							IpScanUtils.writeNamesToFile(altName.get(1).toString());
						}
					}
				}
			}
		}

	}

}
