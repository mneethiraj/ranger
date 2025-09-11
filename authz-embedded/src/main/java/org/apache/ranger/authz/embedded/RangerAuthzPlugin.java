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

package org.apache.ranger.authz.embedded;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.apache.ranger.authz.api.RangerAuthzApiErrorCode;
import org.apache.ranger.authz.api.RangerAuthzException;
import org.apache.ranger.authz.model.RangerAccessContext;
import org.apache.ranger.authz.model.RangerAccessInfo;
import org.apache.ranger.authz.model.RangerAuthzRequest;
import org.apache.ranger.authz.model.RangerAuthzResult;
import org.apache.ranger.authz.model.RangerAuthzResult.AccessDecision;
import org.apache.ranger.authz.model.RangerAuthzResult.AccessResult;
import org.apache.ranger.authz.model.RangerAuthzResult.DataMaskResult;
import org.apache.ranger.authz.model.RangerAuthzResult.PermissionResult;
import org.apache.ranger.authz.model.RangerAuthzResult.PolicyInfo;
import org.apache.ranger.authz.model.RangerAuthzResult.RowFilterResult;
import org.apache.ranger.authz.model.RangerUserInfo;
import org.apache.ranger.authz.util.RangerResourceTemplate;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.model.RangerServiceDef.RangerResourceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResource;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.apache.ranger.plugin.util.RangerAccessRequestUtil;
import org.apache.ranger.plugin.util.ServicePolicies;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class RangerAuthzPlugin {
    private static final Logger LOG = LoggerFactory.getLogger(RangerAuthzPlugin.class);

    private final RangerBasePlugin                    plugin;
    private final Map<String, RangerResourceTemplate> rrnTemplates = new HashMap<>();

    public RangerAuthzPlugin(String serviceType, String serviceName, Properties properties) throws RangerAuthzException {
        plugin = new RangerBasePlugin(getPluginConfig(serviceType, serviceName, properties)) {
            @Override
            public void setPolicies(ServicePolicies policies) {
                super.setPolicies(policies);

                updateResourceTemplates();
            }
        };

        plugin.init();
    }

    public void cleanup() {
        plugin.cleanup();
    }

    private void updateResult(AccessResult from, AccessResult to) {
        if (from == null || to == null || from.getDecision() == null ||
                to.getDecision() == from.getDecision() || // no change in decision
                to.getDecision() == AccessDecision.DENY) { // don't override earlier DENY
            return;
        }

        if (to.getDecision() == null || from.getDecision() == AccessDecision.DENY || from.getDecision() == AccessDecision.NOT_DETERMINED) {
            to.setDecision(from.getDecision());
            to.setPolicy(from.getPolicy());
        }
    }

    public RangerAuthzResult authorize(RangerAuthzRequest request) throws RangerAuthzException {
        RangerUserInfo          userInfo      = request.getUser();
        RangerAccessInfo        access        = request.getAccess();
        RangerAccessContext     context       = request.getContext();
        Set<String>             permissions   = access.getPermissions();
        RangerAuthzResult       ret           = new RangerAuthzResult(request.getRequestId(), new HashMap<>(permissions.size()));
        RangerAccessResource    resource      = getResource(access.getResource(), access.getAttributes());
        RangerAccessRequestImpl accessRequest = new RangerAccessRequestImpl(resource, null, userInfo.getName(), userInfo.getGroups(), userInfo.getRoles());

        accessRequest.setAccessTime(new Date(context.getAccessTime()));
        accessRequest.setClientIPAddress(context.getClientIpAddress());
        accessRequest.setForwardedAddresses(context.getForwardedIpAddresses());
        accessRequest.setAction(access.getAction());
        accessRequest.setClientType(getClientType(context.getAdditionalInfo()));
        accessRequest.setClusterType(getClusterType(context.getAdditionalInfo()));
        accessRequest.setClusterName(getClusterName(context.getAdditionalInfo()));
        accessRequest.setRequestData(getRequestData(context.getAdditionalInfo()));

        boolean hasDeny = false;
        boolean hasAllow = false;
        boolean hasNotDetermined = false;

        for (String permission : permissions) {
            accessRequest.setAccessType(permission);
            accessRequest.setContext(new HashMap<>(context.getAdditionalInfo()));

            PermissionResult permResult = evaluate(accessRequest);

            if (CollectionUtils.isNotEmpty(access.getSubResources())) {
                permResult.setSubResources(new HashMap<>(access.getSubResources().size()));

                for (String subResourceName : access.getSubResources()) {
                    RangerAccessResource subResource = getSubResource(resource, subResourceName);

                    accessRequest.setResource(subResource);
                    accessRequest.setContext(new HashMap<>(context.getAdditionalInfo())); // reset the context

                    PermissionResult subResPermResult = evaluate(accessRequest);

                    if (subResPermResult.getAccess().getDecision() != AccessDecision.ALLOW) {
                        permResult.setAccess(subResPermResult.getAccess());
                    }

                    updateResult(subResPermResult.getAccess(), permResult.getAccess());

                    permResult.getSubResources().put(subResourceName, subResPermResult);
                }
            }

            ret.getPermissions().put(permission, permResult);

            AccessDecision permDecision = permResult.getAccess() == null ? AccessDecision.NOT_DETERMINED : permResult.getAccess().getDecision();

            if (permDecision == AccessDecision.DENY) {
                hasDeny = true;
            } else if (permDecision == AccessDecision.ALLOW) {
                hasAllow = true;
            } else {
                hasNotDetermined = true;
            }
        }

        if (hasDeny) {
            ret.setDecision(AccessDecision.DENY);
        } else if (hasNotDetermined) {
            ret.setDecision(AccessDecision.NOT_DETERMINED);
        } else if (hasAllow) {
            ret.setDecision(AccessDecision.ALLOW);
        }

        return ret;
    }

    private RangerAccessResource getResource(String resource, Map<String, Object> attributes) throws RangerAuthzException {
        Map<String, Object> resourceMap = getResourceAsMap(resource);
        Object              ownerName   = attributes != null ? attributes.get(RangerAccessRequestUtil.KEY_OWNER) : null;

        return new RangerAccessResourceImpl(resourceMap, ownerName != null ? ownerName.toString() : null);
    }

    private RangerAccessResource getSubResource(RangerAccessResource parent, String subResourceName) {
        Map<String, Object> elements = new HashMap<>(parent.getAsMap());

        if (StringUtils.isNotBlank(subResourceName)) {
            String[] parts = subResourceName.split(":", 2);

            elements.put(parts[0], parts.length > 1 ? parts[1] : "");
        }

        return new RangerAccessResourceImpl(elements, parent.getOwnerUser());
    }

    private String getClientType(Map<String, Object> context) {
        Object ret = context != null ? context.get(RangerAccessContext.CONTEXT_INFO_CLIENT_TYPE) : null;

        return ret != null ? ret.toString() : null;
    }

    private String getClusterType(Map<String, Object> context) {
        Object ret = context != null ? context.get(RangerAccessContext.CONTEXT_INFO_CLUSTER_TYPE) : null;

        return ret != null ? ret.toString() : null;
    }

    private String getClusterName(Map<String, Object> context) {
        Object ret = context != null ? context.get(RangerAccessContext.CONTEXT_INFO_CLUSTER_NAME) : null;

        return ret != null ? ret.toString() : null;
    }

    private String getRequestData(Map<String, Object> context) {
        Object ret = context != null ? context.get(RangerAccessContext.CONTEXT_INFO_REQUEST_DATA) : null;

        return ret != null ? ret.toString() : null;
    }

    private PermissionResult toPermissionResult(RangerAccessResult result) {
        PermissionResult ret = new PermissionResult(result.getAccessRequest().getAccessType(), toAccessResult(result));

        if (result.getPolicyType() == RangerPolicy.POLICY_TYPE_DATAMASK) {
            ret.setDataMask(new DataMaskResult(result.getMaskType(), result.getMaskedValue(), ret.getAccess().getPolicy()));
        } else if (result.getPolicyType() == RangerPolicy.POLICY_TYPE_ROWFILTER) {
            ret.setRowFilter(new RowFilterResult(result.getFilterExpr(), ret.getAccess().getPolicy()));
        }

        return ret;
    }

    private AccessResult toAccessResult(RangerAccessResult result) {
        AccessResult ret = new AccessResult();

        if (result.getIsAccessDetermined()) {
            ret.setDecision(result.getIsAllowed() ? AccessDecision.ALLOW : AccessDecision.DENY);
        } else {
            ret.setDecision(AccessDecision.NOT_DETERMINED);
        }

        ret.setPolicy(toPolicyInfo(result));

        return ret;
    }

    private PolicyInfo toPolicyInfo(RangerAccessResult result) {
        return new PolicyInfo(result.getPolicyId(), result.getPolicyVersion());
    }

    private PermissionResult evaluate(RangerAccessRequest request) {
        RangerAccessResult result = plugin.isAccessAllowed(request);
        PermissionResult   ret    = toPermissionResult(result);

        if (plugin.getServiceDefHelper().isRowFilterSupported(request.getResource().getKeys())) {
            RangerAccessResult rowFilterResult = plugin.evalRowFilterPolicies(request, null);

            if (rowFilterResult != null && rowFilterResult.getIsAccessDetermined() && StringUtils.isNotBlank(rowFilterResult.getFilterExpr())) {
                ret.setRowFilter(new RowFilterResult(rowFilterResult.getFilterExpr(), toPolicyInfo(rowFilterResult)));
            }
        }

        if (plugin.getServiceDefHelper().isDataMaskSupported(request.getResource().getKeys())) {
            RangerAccessResult dataMaskResult = plugin.evalDataMaskPolicies(request, null);

            if (dataMaskResult != null && dataMaskResult.getIsAccessDetermined() && StringUtils.isNotBlank(dataMaskResult.getMaskType())) {
                ret.setDataMask(new DataMaskResult(dataMaskResult.getMaskType(), dataMaskResult.getMaskedValue(), toPolicyInfo(dataMaskResult)));
            }
        }

        return ret;
    }

    private Map<String, Object> getResourceAsMap(String resource) throws RangerAuthzException {
        String[]               resourceParts = resource.split(":", 2);
        String                 resourceType  = resourceParts.length > 0 ? resourceParts[0] : null;
        String                 resourceValue = resourceParts.length > 1 ? resourceParts[1] : null;
        RangerResourceTemplate template      = rrnTemplates.get(resourceType);

        if (template == null) {
            throw new RangerAuthzException(RangerAuthzApiErrorCode.INVALID_REQUEST_RESOURCE_TYPE_NOT_FOUND, resourceType);
        }

        Map ret = template.parse(resourceValue);

        if (ret == null) {
            throw new RangerAuthzException(RangerAuthzApiErrorCode.INVALID_REQUEST_RESOURCE_VALUE_FOR_TYPE, resourceValue, resourceType);
        }

        return (Map<String, Object>) ret;
    }

        /*
    private RangerAccessRequest toAccessRequest(RangerAuthzRequest request) throws RangerAuthzException {
        RangerAccessInfo accessInfo = request.getAccess();
        RangerAccessResource resource = new RangerAccessResourceImpl( accessInfo.getResource(), accessInfo.getAttributes());

        return new RangerAccessRequest(
                accessInfo.getResource(),
                request.getUser() != null ? request.getUser().getName() : null,
                accessInfo.getAction(),
                accessInfo.getServiceType(),
                accessInfo.getServiceName(),
                request.getUser() != null ? request.getUser().getGroups() : null,
                accessInfo.,
                accessInfo.getSubResources(),
                accessInfo.getContext());
        return null;
    }
         */

    private void updateResourceTemplates() {
        RangerServiceDef serviceDef = plugin.getServiceDef();

        if (serviceDef != null) {
            for (RangerResourceDef resourceDef : serviceDef.getResources()) {
                try {
                    rrnTemplates.put(resourceDef.getName(), new RangerResourceTemplate(resourceDef.getRrnTemplate()));
                } catch (RangerAuthzException excp) {
                    LOG.warn("failed to create resource template for resourceType={}, rrnTemplate={}", resourceDef.getName(), resourceDef.getRrnTemplate(), excp);
                }
            }
        }
    }

    private static RangerPluginConfig getPluginConfig(String serviceType, String serviceName, Properties properties) {
        return new RangerPluginConfig(serviceType, serviceName, null, properties);
    }
}
