/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.audit.destination;

import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.thirdparty.com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.ranger.audit.model.AuditEventBase;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.credutils.CredentialsProviderUtil;
import org.apache.ranger.authorization.credutils.kerberos.KerberosCredentialsProvider;
import org.elasticsearch.action.admin.indices.open.OpenIndexRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class ElasticSearchAuditDestination extends AuditDestination {
    private static final Logger LOG = LoggerFactory.getLogger(ElasticSearchAuditDestination.class);

    public static final String CONFIG_URLS     = "urls";
    public static final String CONFIG_PORT     = "port";
    public static final String CONFIG_USER     = "user";
    public static final String CONFIG_PWRD     = "password";
    public static final String CONFIG_PROTOCOL = "protocol";
    public static final String CONFIG_INDEX    = "index";
    public static final String CONFIG_PREFIX   = "ranger.audit.elasticsearch";
    public static final String DEFAULT_INDEX   = "ranger_audits";

    private final AtomicReference<RestHighLevelClient> clientRef    = new AtomicReference<>(null);
    private final AtomicLong                           lastLoggedAt = new AtomicLong(0);

    private String  index = CONFIG_INDEX;
    private String  protocol;
    private String  user;
    private int     port;
    private String  password;
    private String  hosts;
    private Subject subject;

    public ElasticSearchAuditDestination() {
        propPrefix = CONFIG_PREFIX;
    }

    public static RestClientBuilder getRestClientBuilder(String urls, String protocol, String user, String password, int port) {
        RestClientBuilder restClientBuilder   = RestClient.builder(MiscUtil.toArray(urls, ",").stream().map(x -> new HttpHost(x, port, protocol)).toArray(HttpHost[]::new));
        ThreadFactory     clientThreadFactory = new ThreadFactoryBuilder().setNameFormat("ElasticSearch rest client %s").setDaemon(true).build();

        if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password) && !user.equalsIgnoreCase("NONE") && !password.equalsIgnoreCase("NONE")) {
            if (password.contains("keytab") && new File(password).exists()) {
                final KerberosCredentialsProvider credentialsProvider = CredentialsProviderUtil.getKerberosCredentials(user, password);
                final Lookup<AuthSchemeProvider>  authSchemeRegistry  = RegistryBuilder.<AuthSchemeProvider>create().register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory()).build();

                restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                    clientBuilder.setThreadFactory(clientThreadFactory);
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    clientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);

                    return clientBuilder;
                });
            } else {
                final CredentialsProvider credentialsProvider = CredentialsProviderUtil.getBasicCredentials(user, password);

                restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                    clientBuilder.setThreadFactory(clientThreadFactory);
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);

                    return clientBuilder;
                });
            }
        } else {
            LOG.error("ElasticSearch Credentials not provided!!");

            final CredentialsProvider credentialsProvider = null;

            restClientBuilder.setHttpClientConfigCallback(clientBuilder -> {
                clientBuilder.setThreadFactory(clientThreadFactory);
                clientBuilder.setDefaultCredentialsProvider(credentialsProvider);

                return clientBuilder;
            });
        }

        return restClientBuilder;
    }

    @Override
    public void init(Properties props, String propPrefix) {
        super.init(props, propPrefix);

        this.protocol = getStringProperty(props, propPrefix + "." + CONFIG_PROTOCOL, "http");
        this.user     = getStringProperty(props, propPrefix + "." + CONFIG_USER, "");
        this.password = getStringProperty(props, propPrefix + "." + CONFIG_PWRD, "");
        this.port     = MiscUtil.getIntProperty(props, propPrefix + "." + CONFIG_PORT, 9200);
        this.index    = getStringProperty(props, propPrefix + "." + CONFIG_INDEX, DEFAULT_INDEX);
        this.hosts    = getHosts();

        LOG.info("Connecting to ElasticSearch: {}", connectionString());

        getClient(); // Initialize client
    }

    @Override
    public void stop() {
        super.stop();

        logStatus();
    }

    /*
     * (non-Javadoc)
     *
     * @see org.apache.ranger.audit.provider.AuditProvider#flush()
     */
    @Override
    public void flush() {
        // Empty flush method
    }

    @Override
    public boolean log(Collection<AuditEventBase> events) {
        boolean ret = false;

        try {
            logStatusIfRequired();
            addTotalCount(events.size());

            RestHighLevelClient client = getClient();

            if (null == client) {
                // ElasticSearch is still not initialized. So need return error
                addDeferredCount(events.size());

                return ret;
            }

            ArrayList<AuditEventBase> eventList   = new ArrayList<>(events);
            BulkRequest               bulkRequest = new BulkRequest();

            try {
                eventList.forEach(event -> {
                    AuthzAuditEvent     authzEvent = (AuthzAuditEvent) event;
                    String              id         = authzEvent.getEventId();
                    Map<String, Object> doc        = toDoc(authzEvent);

                    bulkRequest.add(new IndexRequest(index).id(id).source(doc));
                });
            } catch (Exception ex) {
                addFailedCount(eventList.size());
                logFailedEvent(eventList, ex);
            }

            BulkResponse response = client.bulk(bulkRequest, RequestOptions.DEFAULT);
            if (response.status().getStatus() >= 400) {
                addFailedCount(eventList.size());
                logFailedEvent(eventList, "HTTP " + response.status().getStatus());
            } else {
                BulkItemResponse[] items = response.getItems();

                for (int i = 0; i < items.length; i++) {
                    AuditEventBase   itemRequest  = eventList.get(i);
                    BulkItemResponse itemResponse = items[i];

                    if (itemResponse.isFailed()) {
                        addFailedCount(1);
                        logFailedEvent(Collections.singletonList(itemRequest), itemResponse.getFailureMessage());
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Indexed {}", itemRequest.getEventKey());
                        }

                        addSuccessCount(1);

                        ret = true;
                    }
                }
            }
        } catch (Throwable t) {
            addDeferredCount(events.size());

            logError("Error sending message to ElasticSearch", t);
        }
        return ret;
    }

    public boolean isAsync() {
        return true;
    }

    synchronized RestHighLevelClient getClient() {
        RestHighLevelClient client = clientRef.get();

        if (client == null) {
            synchronized (ElasticSearchAuditDestination.class) {
                client = clientRef.get();

                if (client == null) {
                    client = newClient();

                    clientRef.set(client);
                }
            }
        }

        if (subject != null) {
            KerberosTicket ticket = CredentialsProviderUtil.getTGT(subject);

            try {
                if (ticket != null) {
                    if (new Date().getTime() > ticket.getEndTime().getTime()) {
                        clientRef.set(null);

                        CredentialsProviderUtil.ticketExpireTime80 = 0;

                        client = newClient();

                        clientRef.set(client);
                    } else if (CredentialsProviderUtil.ticketWillExpire(ticket)) {
                        subject = CredentialsProviderUtil.login(user, password);
                    }
                } else {
                    LOG.error("failed to get KerberosTicket for subject {}", subject);
                }
            } catch (PrivilegedActionException e) {
                LOG.error("PrivilegedActionException:", e);

                throw new RuntimeException(e);
            }
        }

        return client;
    }

    Map<String, Object> toDoc(AuthzAuditEvent auditEvent) {
        Map<String, Object> doc = new HashMap<>();

        doc.put("id", auditEvent.getEventId());
        doc.put("access", auditEvent.getAccessType());
        doc.put("enforcer", auditEvent.getAclEnforcer());
        doc.put("agent", auditEvent.getAgentId());
        doc.put("repo", auditEvent.getRepositoryName());
        doc.put("sess", auditEvent.getSessionId());
        doc.put("reqUser", auditEvent.getUser());
        doc.put("reqData", auditEvent.getRequestData());
        doc.put("resource", auditEvent.getResourcePath());
        doc.put("cliIP", auditEvent.getClientIP());
        doc.put("logType", auditEvent.getLogType());
        doc.put("result", auditEvent.getAccessResult());
        doc.put("policy", auditEvent.getPolicyId());
        doc.put("repoType", auditEvent.getRepositoryType());
        doc.put("resType", auditEvent.getResourceType());
        doc.put("reason", auditEvent.getResultReason());
        doc.put("action", auditEvent.getAction());
        doc.put("evtTime", auditEvent.getEventTime());
        doc.put("seq_num", auditEvent.getSeqNum());
        doc.put("event_count", auditEvent.getEventCount());
        doc.put("event_dur_ms", auditEvent.getEventDurationMS());
        doc.put("tags", auditEvent.getTags());
        doc.put("datasets", auditEvent.getDatasets());
        doc.put("projects", auditEvent.getProjects());
        doc.put("cluster", auditEvent.getClusterName());
        doc.put("zoneName", auditEvent.getZoneName());
        doc.put("agentHost", auditEvent.getAgentHostname());
        doc.put("policyVersion", auditEvent.getPolicyVersion());

        return doc;
    }

    private String connectionString() {
        return String.format(Locale.ROOT, "User:%s, %s://%s:%s/%s", user, protocol, hosts, port, index);
    }

    private RestHighLevelClient newClient() {
        RestHighLevelClient restHighLevelClient = null;

        try {
            if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password) && password.contains("keytab") && new File(password).exists()) {
                subject = CredentialsProviderUtil.login(user, password);
            }

            RestClientBuilder restClientBuilder = getRestClientBuilder(hosts, protocol, user, password, port);
            restHighLevelClient = new RestHighLevelClient(restClientBuilder);
            boolean exists = false;

            try {
                exists = restHighLevelClient.indices().open(new OpenIndexRequest(this.index), RequestOptions.DEFAULT).isShardsAcknowledged();
            } catch (Exception e) {
                LOG.warn("Error validating index {}", this.index);
            }

            if (exists) {
                LOG.debug("Index exists");
            } else {
                LOG.info("Index does not exist");
            }

            return restHighLevelClient;
        } catch (Throwable t) {
            lastLoggedAt.updateAndGet(lastLoggedAt -> {
                long now     = System.currentTimeMillis();
                long elapsed = now - lastLoggedAt;

                if (elapsed > TimeUnit.MINUTES.toMillis(1)) {
                    LOG.error("Can't connect to ElasticSearch server: {}", connectionString(), t);

                    return now;
                } else {
                    return lastLoggedAt;
                }
            });

            if (restHighLevelClient != null) {
                try {
                    restHighLevelClient.close();
                    LOG.debug("Closed RestHighLevelClient after failure");
                } catch (IOException e) {
                    LOG.warn("Error closing RestHighLevelClient: {}", e.getMessage(), e);
                }
            }

            return null;
        }
    }

    private String getHosts() {
        String urls = MiscUtil.getStringProperty(props, propPrefix + "." + CONFIG_URLS);

        if (urls != null) {
            urls = urls.trim();
        }

        if ("NONE".equalsIgnoreCase(urls)) {
            urls = null;
        }

        return urls;
    }

    private String getStringProperty(Properties props, String propName, String defaultValue) {
        String value = MiscUtil.getStringProperty(props, propName);

        if (null == value) {
            return defaultValue;
        }

        return value;
    }
}
