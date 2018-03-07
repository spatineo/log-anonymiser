package com.spatineo.anonymisator.dns;

import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class ParallelDnsLookupService implements DnsLookupService, InitializingBean, DisposableBean {
	private static Logger logger = LoggerFactory.getLogger(ParallelDnsLookupService.class);
	
	// Injected by Spring
	private DnsLookupHandler lookupHandler;
	
	private int parallelThreads;
	private long timeoutMillis;
	private int maxCacheSize = -1;
	
	// Set up in afterPropertiesSet()
	private ConcurrentMap<String, DnsLookupResult> lookupCache;
	private ExecutorService executor;
	
	public void setParallelThreads(int parallelThreads) {
		this.parallelThreads = parallelThreads;
	}
	
	public int getParallelThreads() {
		return parallelThreads;
	}
	
	public void setLookupHandler(DnsLookupHandler lookupHandler) {
		this.lookupHandler = lookupHandler;
	}
	
	public DnsLookupHandler getLookupHandler() {
		return lookupHandler;
	}
	
	public void setTimeoutMillis(long timeoutMillis) {
		this.timeoutMillis = timeoutMillis;
	}
	
	public long getTimeoutMillis() {
		return timeoutMillis;
	}
	
	public void setMaxCacheSize(int maxCacheSize) {
		this.maxCacheSize = maxCacheSize;
	}
	
	public int getMaxCacheSize() {
		return maxCacheSize;
	}
	
	
	@Override
	public void afterPropertiesSet() throws Exception {
		Cache<String, DnsLookupResult> tmp;
		if (getMaxCacheSize() > 0) {
			tmp = CacheBuilder.newBuilder()
					.concurrencyLevel(getParallelThreads())
					.maximumSize(getMaxCacheSize())
					.build();
		} else {
			tmp = CacheBuilder.newBuilder()
					.concurrencyLevel(getParallelThreads())
					.build();
		}
		
		lookupCache = tmp.asMap();
		
		logger.debug("Starting thread pool with "+getParallelThreads()+" threads");
		executor = Executors.newFixedThreadPool(getParallelThreads(), new ThreadFactory() {
			@Override
			public Thread newThread(Runnable r) {
				Thread thr = new Thread(r);
				thr.setName("DnsLookup Executor");
				return thr;
			}
		});
	}
	
	@Override
	public void destroy() throws Exception {
		if (executor == null) {
			return;
		}
		
		logger.debug("Shutting down thread pool");
		executor.shutdownNow();
		executor.awaitTermination(getTimeoutMillis() * 5, TimeUnit.MILLISECONDS);
		logger.trace("Thread pool shut down");
	}
	
	@Override
	public Future<DnsLookupResult> lookup(String addr) {
		DnsLookupTask task = new DnsLookupTask(addr);
		return executor.submit(task);
	}
	
	public class DnsLookupTask implements Callable<DnsLookupResult> {
		private String input;
		public DnsLookupTask(String input) {
			this.input = input;
		}
		@Override
		public DnsLookupResult call() throws Exception {
			DnsLookupResult ret = lookupCache.get(input);
			if (ret == null) {
				ret = getLookupHandler().lookup(input);
				lookupCache.putIfAbsent(input, ret);
			}
			return ret;
		}
	}

}
