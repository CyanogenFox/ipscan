package ipscan.model;

import java.util.Objects;

public class IPResponse {
	private String ip;
	private String mask;
	private int thread_count;

	public IPResponse() {
	}

	public IPResponse(String ip, String mask, int thread_count) {
		super();
		this.ip = ip;
		this.mask = mask;
		this.thread_count = thread_count;
	}

	public String getIp() {
		return ip;
	}

	public String getMask() {
		return mask;
	}

	public int getThread_count() {
		return thread_count;
	}

	@Override
	public int hashCode() {
		return Objects.hash(ip, mask, thread_count);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		IPResponse other = (IPResponse) obj;
		return Objects.equals(ip, other.ip) && Objects.equals(mask, other.mask) && thread_count == other.thread_count;
	}

}
