/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ranger.db;

import org.apache.commons.lang.StringUtils;
import org.apache.ranger.common.db.BaseDao;
import org.apache.ranger.entity.XXSecurityZone;
import org.apache.ranger.plugin.model.RangerSecurityZone;
import org.apache.ranger.plugin.model.RangerSecurityZoneHeaderInfo;
import org.springframework.stereotype.Service;

import javax.persistence.NoResultException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class XXSecurityZoneDao extends BaseDao<XXSecurityZone> {
    /**
     * Default Constructor
     */
    public XXSecurityZoneDao(RangerDaoManagerBase daoManager) {
        super(daoManager);
    }

    public XXSecurityZone findByZoneId(Long zoneId) {
        if (zoneId == null) {
            return null;
        }

        try {
            return getEntityManager()
                    .createNamedQuery("XXSecurityZone.findByZoneId", tClass)
                    .setParameter("zoneId", zoneId)
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    public XXSecurityZone findByZoneName(String zoneName) {
        if (StringUtils.isBlank(zoneName)) {
            return null;
        }

        try {
            return getEntityManager()
                    .createNamedQuery("XXSecurityZone.findByZoneName", tClass)
                    .setParameter("zoneName", zoneName)
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    public List<String> findZonesByServiceName(String serviceName) {
        if (serviceName == null) {
            return Collections.emptyList();
        }

        try {
            return getEntityManager().createNamedQuery("XXSecurityZone.findByServiceName", String.class)
                    .setParameter("serviceName", serviceName).getResultList();
        } catch (NoResultException e) {
            return Collections.emptyList();
        }
    }

    public List<String> findZonesByTagServiceName(String tagServiceName) {
        if (tagServiceName == null) {
            return Collections.emptyList();
        }

        try {
            return getEntityManager().createNamedQuery("XXSecurityZone.findByTagServiceName", String.class)
                    .setParameter("tagServiceName", tagServiceName).getResultList();
        } catch (NoResultException e) {
            return Collections.emptyList();
        }
    }

    public List<String> findZoneNamesByUserId(Long userId) {
        if (userId == null) {
            return Collections.emptyList();
        }

        try {
            return getEntityManager().createNamedQuery("XXSecurityZone.findZoneNamesByUserId", String.class)
                    .setParameter("userId", userId).getResultList();
        } catch (NoResultException e) {
            return Collections.emptyList();
        }
    }

    public List<String> findZoneNamesByGroupId(Long groupId) {
        if (groupId == null) {
            return Collections.emptyList();
        }

        try {
            return getEntityManager().createNamedQuery("XXSecurityZone.findZoneNamesByGroupId", String.class)
                    .setParameter("groupId", groupId).getResultList();
        } catch (NoResultException e) {
            return Collections.emptyList();
        }
    }

    public List<RangerSecurityZoneHeaderInfo> findAllZoneHeaderInfos() {
        List<Object[]> results = getEntityManager().createNamedQuery("XXSecurityZone.findAllZoneHeaderInfos", Object[].class).setParameter("unzoneId", RangerSecurityZone.RANGER_UNZONED_SECURITY_ZONE_ID).getResultList();

        List<RangerSecurityZoneHeaderInfo> securityZoneList = new ArrayList<>(results.size());

        for (Object[] result : results) {
            securityZoneList.add(new RangerSecurityZoneHeaderInfo((Long) result[0], (String) result[1]));
        }

        return securityZoneList;
    }

    public List<RangerSecurityZoneHeaderInfo> findAllZoneHeaderInfosByServiceId(Long serviceId, Boolean isTagService) {
        if (serviceId == null) {
            return Collections.emptyList();
        }

        List<Object[]> results;

        if (isTagService) {
            results = getEntityManager().createNamedQuery("XXSecurityZone.findAllZoneHeaderInfosByTagServiceId", Object[].class)
                    .setParameter("tagServiceId", serviceId)
                    .getResultList();
        } else {
            results = getEntityManager().createNamedQuery("XXSecurityZone.findAllZoneHeaderInfosByServiceId", Object[].class)
                    .setParameter("serviceId", serviceId)
                    .getResultList();
        }

        List<RangerSecurityZoneHeaderInfo> securityZoneList = new ArrayList<>(results.size());

        for (Object[] result : results) {
            securityZoneList.add(new RangerSecurityZoneHeaderInfo((Long) result[0], (String) result[1]));
        }

        return securityZoneList;
    }

    public List<XXSecurityZone> getAllZoneIdNames() {
        @SuppressWarnings("unchecked")
        List<Object[]> results = getEntityManager().createNamedQuery("XXSecurityZone.getAllZoneIdNames").getResultList();

        List<XXSecurityZone> securityZoneList = new ArrayList<XXSecurityZone>(results.size());
        for (Object[] result : results) {
            XXSecurityZone xXSecurityZone = new XXSecurityZone();
            xXSecurityZone.setId((Long) result[0]);
            xXSecurityZone.setName((String) result[1]);
            securityZoneList.add(xXSecurityZone);
        }

        return securityZoneList;
    }
}
