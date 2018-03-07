package com.spatineo.anonymisator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AnonymiserProcessor {

	private static final String IPv4_MATCHER = "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
	private static final String IPv6_MATCHER= "(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
	
	/**
	 * Matcher with negative and positive lookahead testing that we only match IP addresses that are surrounded
	 * by whitespace
	 */
	private static final Pattern IP_MATCHER = Pattern.compile("(?<=\\s|^)("+IPv4_MATCHER+"|"+IPv6_MATCHER+")(?=\\s|$)");
	
	private IpAddressAnonymiser ipAddressAnonymiser;
	
	public void setIpAddressAnonymiser(IpAddressAnonymiser ipAddressAnonymiser) {
		this.ipAddressAnonymiser = ipAddressAnonymiser;
	}
	
	public IpAddressAnonymiser getIpAddressAnonymiser() {
		return ipAddressAnonymiser;
	}
	
	public void process(Reader in, Writer out) throws IOException {
		BufferedReader br = new BufferedReader(in);
		String line;
		
		while ((line = br.readLine()) != null) {
			String processed = process(line);
			out.write(processed);
			out.write("\n");
		}
		
		out.flush();
	}

	public String process(String line) {
		
		StringBuffer output = new StringBuffer();
		
		Matcher m = IP_MATCHER.matcher(line);
		int lastMatchEndIndex = 0;
		while (m.find()) {
			String beforeMatch = line.substring(lastMatchEndIndex, m.start());
			lastMatchEndIndex = m.end();
			
			output.append(beforeMatch);
			
			String result = getIpAddressAnonymiser().processAddressString(m.group(1));
			output.append(result);
		}
		
		String lastPart = line.substring(lastMatchEndIndex);
		
		output.append(lastPart);
		

		return output.toString();
	}
}
