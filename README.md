# Log Anonymiser

This tool is a command line anonymiser for access log files. The tool searches for IPv4 and IPv6 addresses in input files and anonymises them by removing a configurable number of bits from the end of the addresses. In addition to just anonymising, the tool also performs a reverse DNS lookup of the original address and stores the first level subdomain of the address.

The tool has been developed by Spatineo Inc specifically for use with [Spatineo Monitor](https://www.spatineo.com/monitor/) log analysis. The tool is released under GPLv3 to allow our users and others to build and share developments of the tool.

Source code is available at [GitHub](https://github.com/spatineo/log-anonymiser)

Released versions are available on [Maven Central](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.spatineo%22%20a%3A%22log-anonymiser%22)

The log anonymiser is developed using Java and requires Java 8 to run.

## Usage

When running the anonymiser, you need to specify the input and output files along with parameters. Default parameters will work for most users.

<pre>
> java -jar log-anonymiser-0.0.3.jar
Usage: java -jar log-anonymisator.jar [options] inputfile outputfile
	The following options are supported:
	  --dns.allowprivate   Return full private DNS names (e.g. hello.local) when DNS returns them
	  --dns.disabled       Disable DNS lookups (enabled by default)
	  --dns.server=value   DNS server(s) to use as a comma-delimited list, for example --dns.server=8.8.8.8,4.4.4.4 for Google public DNS (use system settings by default)
	  --dns.timeoutmillis  DNS lookup timeout in milliseconds (default 30000)
	  --help               Display this message
	  --mask.ipv4=value    How many bits in IPv4 addressess to mask / anonymise (default 8)
	  --mask.ipv6=value    How many bits in IPv6 addressess to mask / anonymise (default 80)
	  --threads            How many concurrent threads are used in parallel (default 32)
</pre>

## Anonymising logs for Spatineo Monitor

Users of Spatineo Monitor should use this tool to process their log files before sending the logs to Spatineo. This tool can be easily integrated into the script that automates transfer of log files to Spatineo. The only change required to the usual upload script is that anonymising is done before sending the file.

# How it works

This tool works by detecting IP addresses in text files. It reads a file, anonymises the IP addresses and writes the output into a separate file. All IP addresses found on a single row will be anonymised.  This approach means the tool is compatible with almost all access log file formats.

When the tool resolves reverse DNS names, it will only return the top level public domain name (e.g. google.com for anything.google.com). This simplification is done only for DNS names with publicly available suffixes like com, net, de, co.uk, etc. DNS names with non-public suffixes are disregarded unless the flag --dns.allowprivate is used. If the flag is used, full DNS names without simplification are produced in the output log file.

## Example

Consider anonymising a NCSA combined styled log file. It has rows such as:

<pre>
123.123.123.123 - - [01/Mar/2018:09:11:38 +0300] "GET /foo/bar HTTP/1.0" 200 42 "-" "Some HTTP Client"
</pre>

The row represents a request from address 123.123.123.123. This tool anonymises the address by the specified number of bits (8 by default) that results in the address 123.123.123.0/24.

In addition to anonymisation, the tool performs a reverse DNS lookup for the original address to identify the source of the request. To protect the privacy of users, the entire reverse DNS name is not used, but only the first level subdomain. In this example, if the reverse name for 123.123.123.123 would be server.company.co.uk, we would store only company.co.uk.

The final anonymised row will look like this:

<pre>
{!1{123.123.123.0/24,company.co.uk}} - - [01/Mar/2018:09:11:38 +0300] "GET /foo/bar HTTP/1.0" 200 42 "-" "Some HTTP Client"
</pre>

Curly braces, the exclamation mark, and a version number (1) are used to help log analysis software to parse this special format.

## Todo

* Read and write GZIP compressed files.
* [HAProxy](http://www.haproxy.org/) log files contain IP addresses along with client TCP ports (for example 123.123.123.123:1432). These addresses are currently not identified.

## Reporting bugs

Please report any issues found to the project GitHub issue tracker at https://github.com/spatineo/log-anonymiser/issues

