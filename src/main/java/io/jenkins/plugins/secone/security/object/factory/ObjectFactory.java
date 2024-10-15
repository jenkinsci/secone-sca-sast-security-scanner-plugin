package io.jenkins.plugins.secone.security.object.factory;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.client.RestTemplate;

import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;

public class ObjectFactory {

	public HttpPost createHttpPost(String uri) throws URISyntaxException {
		HttpPost post = new HttpPost(uri);

		// Set proxy if needed
		RequestConfig config = getRequestConfig(new URI(uri));
		if (config != null) {
			post.setConfig(config);
		}

		return post;
	}

	public CloseableHttpClient createHttpClient() {
		CloseableHttpClient client;

		ProxyConfiguration proxy = getJenkinsProxyConfiguration();
		if (proxy != null) {
			HttpHost proxyHost = new HttpHost(proxy.name, proxy.port);
			client = HttpClients.custom().setProxy(proxyHost).build();
		} else {
			client = HttpClients.custom().build();
		}

		return client;
	}

	public String getGitFolderConfigPath() {
		return ".git" + File.separator + "config";
	}

	public RestTemplate createRestTemplate() {
		return new RestTemplate();
	}

	private ProxyConfiguration getJenkinsProxyConfiguration() {
		Jenkins jenkins = Jenkins.get();
		return jenkins != null ? jenkins.proxy : null;
	}

	public MultipartEntityBuilder createMultipartBodyBuilder() {
		return MultipartEntityBuilder.create();
	}

	private RequestConfig getRequestConfig(URI uri) {
		ProxyConfiguration proxy = getJenkinsProxyConfiguration();
		if (proxy != null && shouldUseProxy(proxy, uri.getHost())) {
			HttpHost proxyHost = new HttpHost(proxy.name, proxy.port);
			return RequestConfig.custom().setProxy(proxyHost).build();
		}
		return null;
	}

	private boolean shouldUseProxy(ProxyConfiguration proxy, String host) {
		if (proxy == null || host == null) {
			return false;
		}

		List<Pattern> noProxyHostPatterns = proxy.getNoProxyHostPatterns();
		for (Pattern noProxyHostPattern : noProxyHostPatterns) {
			if (noProxyHostPattern.matcher(host).matches()) {
				return false;
			}
		}
		return true;
	}
}
