package com.spatineo.anonymisator.dns;

import java.util.concurrent.ConcurrentMap;

import org.springframework.beans.factory.InitializingBean;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.spatineo.anonymisator.AnonymiserConfiguration;

public class DnsjavaLookupHandlerImpl implements DnsLookupHandler, InitializingBean {
	
	private AnonymiserConfiguration anonymiserConfiguration;
	
	private int maxCacheSize = -1;
	private Resolver resolver;
	
	// Set up in afterPropertiesSet()
	private ConcurrentMap<String, DnsLookupResult> lookupCache;
	
	
	public void setMaxCacheSize(int maxCacheSize) {
		this.maxCacheSize = maxCacheSize;
	}
	
	public int getMaxCacheSize() {
		return maxCacheSize;
	}
	
	public void setResolver(Resolver resolver) {
		this.resolver = resolver;
	}
	
	public Resolver getResolver() {
		return resolver;
	}
	
	public void setAnonymiserConfiguration(AnonymiserConfiguration anonymiserConfiguration) {
		this.anonymiserConfiguration = anonymiserConfiguration;
	}
	
	public AnonymiserConfiguration getAnonymiserConfiguration() {
		return anonymiserConfiguration;
	}
	
	@Override
	public void afterPropertiesSet() throws Exception {
		// Cache
		Cache<String, DnsLookupResult> tmp;
		if (getMaxCacheSize() > 0) {
			tmp = CacheBuilder.newBuilder()
					.concurrencyLevel(getAnonymiserConfiguration().getParallelThreads())
					.maximumSize(getMaxCacheSize())
					.build();
		} else {
			tmp = CacheBuilder.newBuilder()
					.concurrencyLevel(getAnonymiserConfiguration().getParallelThreads())
					.build();
		}
		
		lookupCache = tmp.asMap();
	}
	
	@Override
	public DnsLookupResult lookup(String addr) throws Exception {
		
		DnsLookupResult ret = lookupCache.get(addr);
		if (ret == null) {
			ret = lookupFromDNS(addr);
			lookupCache.putIfAbsent(addr, ret);
		}
		return ret;
		
	}

	// TODO: ipv6
	// Visibility for tests only
	DnsLookupResult lookupFromDNS(String addr) throws Exception {
		Name name = ReverseMap.fromAddress(addr);
		int type = Type.PTR;
		int dclass = DClass.IN;
		Record rec = Record.newRecord(name, type, dclass);
		Message query = Message.newQuery(rec);
		
		Message response = getResolver().send(query);

		DnsLookupResult ret = new DnsLookupResult();
		
		Record[] answers = response.getSectionArray(Section.ANSWER);
		if (answers.length == 0) {
			ret.setSuccess(false);
			return ret;
		}
		
		String reverseName = answers[0].rdataToString();
		// Remove end dot
		if (reverseName != null) {
			while (reverseName.length() > 0 && reverseName.charAt(reverseName.length()-1) == '.') {
				reverseName = reverseName.substring(0, reverseName.length()-1);
			}
		}
		ret.setReverseName(reverseName);
		ret.setSuccess(true);
		return ret;
	}

}
