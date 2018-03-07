package com.spatineo.anonymisator.dns;

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class DnsjavaLookupHandlerImpl implements DnsLookupHandler, InitializingBean {
	private DnsLookupConfiguration dnsLookupConfiguration;
	
	// Set up in afterPropertiesSet()
	private Resolver resolver;
	
	public void setDnsLookupConfiguration(DnsLookupConfiguration dnsLookupConfiguration) {
		this.dnsLookupConfiguration = dnsLookupConfiguration;
	}
	
	public DnsLookupConfiguration getDnsLookupConfiguration() {
		return dnsLookupConfiguration;
	}
	
	@Override
	public void afterPropertiesSet() throws Exception {
		List<String> servers = getDnsLookupConfiguration().getServers();
		if (servers == null) {
			resolver = new ExtendedResolver();
		} else {
			resolver = new ExtendedResolver(servers.toArray(new String[]{}));
		}
		
		long timeout = getDnsLookupConfiguration().getTimeoutMillis();
		long millis = timeout % 1000;
		long secs = (timeout - millis) / 1000l;
		resolver.setTimeout((int) secs, (int) millis);	
	}
	
	// TODO: ipv6
	@Override
	public DnsLookupResult lookup(String addr) throws Exception {
		Name name = ReverseMap.fromAddress(addr);
		int type = Type.PTR;
		int dclass = DClass.IN;
		Record rec = Record.newRecord(name, type, dclass);
		Message query = Message.newQuery(rec);
		
		Message response = resolver.send(query);

		Record[] answers = response.getSectionArray(Section.ANSWER);
		if (answers.length == 0) {
			return null;
		}
		
		DnsLookupResult ret = new DnsLookupResult();
		String reverseName = answers[0].rdataToString();
		if (reverseName != null) {
			while (reverseName.length() > 0 && reverseName.charAt(reverseName.length()-1) == '.') {
				reverseName = reverseName.substring(0, reverseName.length()-1);
			}
		}
		ret.setReverseName(reverseName);
		return ret;
	}

}
