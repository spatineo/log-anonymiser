package com.spatineo.anonymisator;

/*-
 * #%L
 * log-anonymisator
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 Spatineo Inc
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AnonymiserProcessor {
	private static Logger logger = LoggerFactory.getLogger(AnonymiserProcessor.class);
	
	private static final String IPv4_MATCHER = "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
	private static final String IPv6_MATCHER= "(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
	
	/**
	 * Matcher with negative and positive lookahead testing that we only match IP addresses that are surrounded
	 * by whitespace or a comma. The comma is necessary for X-Forwarded-For fields where addresses are separated by commas
	 */
	private static final Pattern IP_MATCHER = Pattern.compile("(?<=[\\s,]|^)("+IPv4_MATCHER+"(:[0-9]+)?|"+IPv6_MATCHER+")(?=[\\s,]|$)");
	
	private IpAddressAnonymiser ipAddressAnonymiser;
	private int parallelThreads;
	private long timeoutMillis;
	
	public void setIpAddressAnonymiser(IpAddressAnonymiser ipAddressAnonymiser) {
		this.ipAddressAnonymiser = ipAddressAnonymiser;
	}
	
	public IpAddressAnonymiser getIpAddressAnonymiser() {
		return ipAddressAnonymiser;
	}
	
	public int getParallelThreads() {
		return parallelThreads;
	}
	
	public void setParallelThreads(int parallelThreads) {
		this.parallelThreads = parallelThreads;
	}
	
	public void setTimeoutMillis(long timeoutMillis) {
		this.timeoutMillis = timeoutMillis;
	}
	
	public long getTimeoutMillis() {
		return timeoutMillis;
	}
	
	
	
	public void process(Reader in, Writer out) throws Exception {
		if (getParallelThreads() > 1) {
			logger.info("Using multithreading");
			processParallel(in, out);
		} else {
			logger.info("Using single-thread mode");
			processSingleThread(in, out);
		}
	}
	
	private void processSingleThread(Reader in, Writer out) throws Exception {
		BufferedReader br = new BufferedReader(in);
		String line;
		
		
		while ((line = br.readLine()) != null) {
			String processed = process(line);
			out.write(processed);
			out.write("\n");
		}
	}

	void processParallel(Reader in, Writer out) throws Exception {
		ExecutorService executor = Executors.newFixedThreadPool(getParallelThreads(), new ThreadFactory() {
			@Override
			public Thread newThread(Runnable r) {
				Thread ret = new Thread(r);
				ret.setName("AnonymiserProcessor.Thread");
				return ret;
			}
		});
		
		Thread inputThread = null;
		
		try {
			AtomicBoolean allInputRead = new AtomicBoolean(false);
			Semaphore semaphore = new Semaphore(getParallelThreads());
			
			ConcurrentLinkedQueue<Future<String>> processQueue = new ConcurrentLinkedQueue<>();

			// This thread will push input lines to the processing threads. Note that inputThread might be null
			// if there is no need to create an additional thread (due to less rows in inputFile than parallelThreads)
			inputThread = startInputThread(executor, semaphore, processQueue, allInputRead, in);
			
			long stallMs = 10;
			
			while(!allInputRead.get() || !processQueue.isEmpty()) { // <- if input is slow, the processQueue might be starved, so this doesn't work
				Future<String> next = processQueue.poll();
				
				if (next == null) {
					logger.trace("Reading input is stalled, waiting for "+stallMs+"ms");
					Thread.sleep(stallMs);
					stallMs = Math.min(stallMs * 2, 2000l);
					continue;
				}
				
				stallMs = 10;
				
				// Wait until the row is completed, then release the semaphore
				String processed = next.get();
				semaphore.release();
				
				out.write(processed);
				out.write("\n");
			}

		} finally {
			logger.debug("Shutting down executor service");
			executor.shutdownNow();
			executor.awaitTermination(getTimeoutMillis()*3, TimeUnit.MILLISECONDS);
			if (inputThread != null) {
				inputThread.join();
			}
		}
	}

	private Thread startInputThread(ExecutorService executor, Semaphore semaphore, ConcurrentLinkedQueue<Future<String>> processQueue, AtomicBoolean allInputRead, Reader in) throws IOException {
		BufferedReader br = new BufferedReader(in);

		while (semaphore.tryAcquire()) {
			String line = br.readLine();
		 
			if (line == null) {
				logger.debug("Input file has less rows than parallel threads, no AnonymiserInputThread necessary");
				allInputRead.set(true);
				return null;
			}
			
			Future<String> output = executor.submit(new Callable<String>() {
				@Override
				public String call() throws Exception {
					return process(line);
				}
			});
			processQueue.add(output);
		}
		
		logger.debug("Starting AnonymiserInputThread to read input data for processing");
		Thread ret = new Thread(new Runnable() {
			
			@Override
			public void run() {
				try {
					while (true) {
						String tmp = br.readLine();
						if (tmp == null) {
							logger.trace("End of file, exiting thread");
							return;
						}
						
						// Wait for a slot, i.e. the semaphore
						semaphore.acquire();
						Future<String> output = executor.submit(new Callable<String>() {
							@Override
							public String call() throws Exception {
								return process(tmp);
							}
						});
						processQueue.add(output);
					}
				} catch(IOException | InterruptedException e) {
					logger.error("Error while processing input", e);
				} finally {
					allInputRead.set(true);
				}
			}
		}, "AnonymiserInputThread");
		
		ret.start();
		
		return ret;
	}

	String process(String line) {
		
		StringBuffer output = new StringBuffer();
		
		Matcher m = IP_MATCHER.matcher(line);
		int lastMatchEndIndex = 0;
		while (m.find()) {
			String beforeMatch = line.substring(lastMatchEndIndex, m.start());
			lastMatchEndIndex = m.end();
			
			output.append(beforeMatch);
			
			String result = getIpAddressAnonymiser().processAddressString(m.group(1));
			
			// Handle possible IPv4 port
			String port = m.group(2);
			if (port != null && port.length() > 0) {
				result += port;
			}
			
			output.append(result);
		}
		
		String lastPart = line.substring(lastMatchEndIndex);
		
		output.append(lastPart);
		

		return output.toString();
	}
}
