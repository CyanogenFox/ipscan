package ipscan.client;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.util.List;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;

import ipscan.model.ScanThread;
import ipscan.model.utils.IpScanUtils;

public class SimpleClient {

	private HttpGet request;// TODO delete?

	public SimpleClient() {
		request = new HttpGet();
	}

	// TODO request timeout, handle exceptions properly, threads_count cant be 0
	public void getEntity(String ip, String mask, int i_threads)
			throws CertificateParsingException, UnknownHostException, IOException, InterruptedException {
		List<String> ipList = IpScanUtils.ipMaskToList(ip, mask);
		ScanThread[] scanThreads = new ScanThread[i_threads];

		PoolingHttpClientConnectionManager pcm = new PoolingHttpClientConnectionManager();
		pcm.setMaxTotal(i_threads);
		pcm.setDefaultMaxPerRoute(1);
		CloseableHttpClient client = HttpClients.custom().setConnectionManager(pcm).build();

//		SSLConnectionSocketFactory scsf = new SSLConnectionSocketFactory(SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build(),
//																		NoopHostnameVerifier.INSTANCE);
//		client = HttpClients.custom().setSSLSocketFactory(scsf).build(); // TODO probably not the best idea because of NoopHostnameVerifier

		int iPerThread = ipList.size() / i_threads + 1;

		for (int i = 0, sub_i = 0, sub_z = iPerThread; i < scanThreads.length; i++) {
			if (ipList.size() >= i_threads) {
				if (sub_i < ipList.size()) {
					scanThreads[i] = new ScanThread(client,
							ipList.subList(sub_i, sub_z >= ipList.size() ? ipList.size() - 1 : sub_z));
					sub_i = sub_z + 1;
					sub_z += iPerThread;
				}
			} else {
				if (i < i_threads) {
					scanThreads[i] = new ScanThread(client, ipList.get(i));
				} else
					break;
			}
		}
		for (ScanThread thread : scanThreads) {
			if (thread != null)
				thread.start();
		}
		for (ScanThread thread : scanThreads) {
			if (thread != null)
				thread.join();
		}

		System.out.println("end of threads");// TODO
	}

	public HttpGet getRequset() {
		return request;
	}

	public void setRequest(String url) {
		this.request = new HttpGet(url);
	}

}
