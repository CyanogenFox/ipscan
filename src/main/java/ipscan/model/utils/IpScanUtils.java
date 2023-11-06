package ipscan.model.utils;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.net.util.SubnetUtils;

public class IpScanUtils {

//	private final static String ADDRESS = "http://localhost:8080";

	public static List<String> ipMaskToList(String ip, String mask) {
		try {
			SubnetUtils utils = new SubnetUtils(ip, convertMask(mask));
			String[] allIps = utils.getInfo().getAllAddresses();
			List<String> ipList = new ArrayList<>();
			for (String i : allIps) {
				ipList.add(i);
			}
			return ipList;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static String convertMask(String mask) {
		int cidr = Integer.valueOf(mask.substring(1));
		long bits = 0;
		bits = 0xffffffff ^ (1 << 32 - cidr) - 1;
		return String.format("%d.%d.%d.%d", (bits & 0x0000000000ff000000L) >> 24, (bits & 0x0000000000ff0000) >> 16,
				(bits & 0x0000000000ff00) >> 8, bits & 0xff);
	}

	public static void writeNamesToFile(String string) throws IOException {
		/*
		 * no duplicate checker, no specification on folder. Change if needed
		 */
		BufferedWriter bw = new BufferedWriter(new FileWriter("DN_names.txt", true));
		bw.write(string);
		bw.newLine();
		bw.flush();
		bw.close();
	}

}
