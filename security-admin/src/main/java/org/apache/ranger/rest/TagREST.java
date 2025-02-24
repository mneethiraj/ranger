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

package org.apache.ranger.rest;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.ranger.biz.AssetMgr;
import org.apache.ranger.biz.RangerBizUtil;
import org.apache.ranger.biz.ServiceDBStore;
import org.apache.ranger.biz.TagDBStore;
import org.apache.ranger.common.MessageEnums;
import org.apache.ranger.common.RESTErrorUtil;
import org.apache.ranger.common.RangerSearchUtil;
import org.apache.ranger.db.RangerDaoManager;
import org.apache.ranger.entity.XXService;
import org.apache.ranger.entity.XXServiceDef;
import org.apache.ranger.plugin.model.RangerPluginInfo;
import org.apache.ranger.plugin.model.RangerService;
import org.apache.ranger.plugin.model.RangerServiceResource;
import org.apache.ranger.plugin.model.RangerTag;
import org.apache.ranger.plugin.model.RangerTagDef;
import org.apache.ranger.plugin.model.RangerTagResourceMap;
import org.apache.ranger.plugin.store.EmbeddedServiceDefsUtil;
import org.apache.ranger.plugin.store.PList;
import org.apache.ranger.plugin.store.RangerServiceResourceSignature;
import org.apache.ranger.plugin.store.TagStore;
import org.apache.ranger.plugin.store.TagValidator;
import org.apache.ranger.plugin.util.RangerPerfTracer;
import org.apache.ranger.plugin.util.RangerRESTUtils;
import org.apache.ranger.plugin.util.SearchFilter;
import org.apache.ranger.plugin.util.ServiceTags;
import org.apache.ranger.service.RangerServiceResourceService;
import org.apache.ranger.service.RangerServiceResourceWithTagsService;
import org.apache.ranger.service.RangerTagDefService;
import org.apache.ranger.service.RangerTagResourceMapService;
import org.apache.ranger.service.RangerTagService;
import org.apache.ranger.view.RangerServiceResourceWithTagsList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;

import java.util.List;
import java.util.Map;

@Path(TagRESTConstants.TAGDEF_NAME_AND_VERSION)
@Component
@Scope("request")
@Transactional(propagation = Propagation.REQUIRES_NEW)
public class TagREST {
    private static final Logger LOG      = LoggerFactory.getLogger(TagREST.class);
    private static final Logger PERF_LOG = RangerPerfTracer.getPerfLogger("rest.TagREST");

    public static final String Allowed_User_List_For_Tag_Download = "tag.download.auth.users";

    @Autowired
    RESTErrorUtil restErrorUtil;

    @Autowired
    ServiceDBStore svcStore;

    @Autowired
    TagDBStore tagStore;

    @Autowired
    RangerDaoManager daoManager;

    @Autowired
    RangerBizUtil bizUtil;

    @Autowired
    AssetMgr assetMgr;

    TagValidator validator;

    @Autowired
    RangerSearchUtil searchUtil;

    @Autowired
    RangerTagService tagService;

    @Autowired
    RangerTagDefService tagDefService;

    @Autowired
    RangerServiceResourceService rangerServiceResourceService;

    @Autowired
    RangerServiceResourceWithTagsService rangerServiceResourceWithTagsService;

    @Autowired
    RangerTagResourceMapService rangerTagResourceMapService;

    public TagREST() {
    }

    @PostConstruct
    public void initStore() {
        validator = new TagValidator();

        tagStore.setServiceStore(svcStore);
        validator.setTagStore(tagStore);
    }

    @POST
    @Path(TagRESTConstants.TAGDEFS_RESOURCE)
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagDef createTagDef(RangerTagDef tagDef, @DefaultValue("true") @QueryParam("updateIfExists") boolean updateIfExists) {
        LOG.debug("==> TagREST.createTagDef({}, {})", tagDef, updateIfExists);

        RangerTagDef ret;

        try {
            RangerTagDef exist = validator.preCreateTagDef(tagDef, updateIfExists);

            if (exist == null) {
                ret = tagStore.createTagDef(tagDef);
            } else if (updateIfExists) {
                ret = updateTagDef(exist.getId(), exist);
            } else {
                throw new Exception("tag-definition with Id " + exist.getId() + " already exists");
            }
        } catch (Exception excp) {
            LOG.error("createTagDef({}) failed", tagDef, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.createTagDef({}, {}): {}", tagDef, updateIfExists, ret);

        return ret;
    }

    @PUT
    @Path(TagRESTConstants.TAGDEF_RESOURCE + "{id}")
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagDef updateTagDef(@PathParam("id") Long id, RangerTagDef tagDef) {
        LOG.debug("==> TagREST.updateTagDef({})", id);

        if (tagDef.getId() == null) {
            tagDef.setId(id);
        } else if (!tagDef.getId().equals(id)) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, "tag name mismatch", true);
        }

        RangerTagDef ret;

        try {
            ret = tagStore.updateTagDef(tagDef);
        } catch (Exception excp) {
            LOG.error("updateTagDef({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.updateTagDef({})", id);

        return ret;
    }

    @DELETE
    @Path(TagRESTConstants.TAGDEF_RESOURCE + "{id}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagDef(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.deleteTagDef({})", id);

        try {
            tagStore.deleteTagDef(id);
        } catch (Exception excp) {
            LOG.error("deleteTagDef({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteTagDef({})", id);
    }

    @DELETE
    @Path(TagRESTConstants.TAGDEF_RESOURCE + "guid/{guid}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagDefByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.deleteTagDefByGuid({})", guid);

        try {
            RangerTagDef exist = tagStore.getTagDefByGuid(guid);

            if (exist != null) {
                tagStore.deleteTagDef(exist.getId());
            }
        } catch (Exception excp) {
            LOG.error("deleteTagDef({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteTagDefByGuid({})", guid);
    }

    @GET
    @Path(TagRESTConstants.TAGDEF_RESOURCE + "{id}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagDef getTagDef(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.getTagDef({})", id);

        RangerTagDef ret;

        try {
            ret = tagStore.getTagDef(id);
        } catch (Exception excp) {
            LOG.error("getTagDef({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (ret == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Not found", true);
        }

        LOG.debug("<== TagREST.getTagDef({}): {}", id, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGDEF_RESOURCE + "guid/{guid}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagDef getTagDefByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.getTagDefByGuid({})", guid);

        RangerTagDef ret;

        try {
            ret = tagStore.getTagDefByGuid(guid);
        } catch (Exception excp) {
            LOG.error("getTagDefByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (ret == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Not found", true);
        }

        LOG.debug("<== TagREST.getTagDefByGuid({}): {}", guid, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGDEF_RESOURCE + "name/{name}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagDef getTagDefByName(@PathParam("name") String name) {
        LOG.debug("==> TagREST.getTagDefByName({})", name);

        RangerTagDef ret;

        try {
            ret = tagStore.getTagDefByName(name);
        } catch (Exception excp) {
            LOG.error("getTagDefByName({}) failed", name, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (ret == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Not found", true);
        }

        LOG.debug("<== TagREST.getTagDefByName({}): {}", name, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGDEFS_RESOURCE)
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public List<RangerTagDef> getAllTagDefs() {
        LOG.debug("==> TagREST.getAllTagDefs()");

        List<RangerTagDef> ret;

        try {
            ret = tagStore.getTagDefs(new SearchFilter());
        } catch (Exception excp) {
            LOG.error("getAllTagDefs() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (ret == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Not found", true);
        }

        LOG.debug("<== TagREST.getAllTagDefs()");

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGDEFS_RESOURCE_PAGINATED)
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public PList<RangerTagDef> getTagDefs(@Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getTagDefs()");

        final PList<RangerTagDef> ret;

        try {
            SearchFilter filter = searchUtil.getSearchFilter(request, tagDefService.sortFields);

            ret = tagStore.getPaginatedTagDefs(filter);
        } catch (Exception excp) {
            LOG.error("getTagDefs() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (ret == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Not found", true);
        }

        LOG.debug("<== TagREST.getTagDefs(): count={}", ret.getList() == null ? 0 : ret.getList().size());

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGTYPES_RESOURCE)
    @Produces("application/json")
    public List<String> getTagTypes() {
        LOG.debug("==> TagREST.getTagTypes()");

        // check for ADMIN access
        if (!bizUtil.isAdmin()) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_FORBIDDEN, "User don't have permission to perform this action", true);
        }

        List<String> ret;

        try {
            ret = tagStore.getTagTypes();
        } catch (Exception excp) {
            LOG.error("getTagTypes() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getTagTypes(): count={}", (ret != null ? ret.size() : 0));

        return ret;
    }

    @POST
    @Path(TagRESTConstants.TAGS_RESOURCE)
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTag createTag(RangerTag tag, @DefaultValue("true") @QueryParam("updateIfExists") boolean updateIfExists) {
        LOG.debug("==> TagREST.createTag({}, {})", tag, updateIfExists);

        RangerTag ret;

        try {
            RangerTag exist = validator.preCreateTag(tag);

            if (exist == null) {
                ret = tagStore.createTag(tag);
            } else if (updateIfExists) {
                ret = updateTag(exist.getId(), tag);
            } else {
                throw new Exception("tag with Id " + exist.getId() + " already exists");
            }
        } catch (Exception excp) {
            LOG.error("createTag({}) failed", tag, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.createTag({}, {}): {}", tag, updateIfExists, ret);

        return ret;
    }

    @PUT
    @Path(TagRESTConstants.TAG_RESOURCE + "{id}")
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTag updateTag(@PathParam("id") Long id, RangerTag tag) {
        RangerTag ret;

        try {
            validator.preUpdateTag(id, tag);

            ret = tagStore.updateTag(tag);
        } catch (Exception excp) {
            LOG.error("updateTag({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.updateTag({}): {}", id, ret);

        return ret;
    }

    @PUT
    @Path(TagRESTConstants.TAG_RESOURCE + "guid/{guid}")
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTag updateTagByGuid(@PathParam("guid") String guid, RangerTag tag) {
        LOG.debug("==> TagREST.updateTagByGuid({})", guid);

        RangerTag ret;

        try {
            validator.preUpdateTagByGuid(guid, tag);

            ret = tagStore.updateTag(tag);
        } catch (Exception excp) {
            LOG.error("updateTagByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.updateTagByGuid({}): {}", guid, ret);

        return ret;
    }

    @DELETE
    @Path(TagRESTConstants.TAG_RESOURCE + "{id}")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTag(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.deleteTag({})", id);

        try {
            validator.preDeleteTag(id);
            tagStore.deleteTag(id);
        } catch (Exception excp) {
            LOG.error("deleteTag({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteTag({})", id);
    }

    @DELETE
    @Path(TagRESTConstants.TAG_RESOURCE + "guid/{guid}")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.deleteTagByGuid({})", guid);

        try {
            RangerTag exist = validator.preDeleteTagByGuid(guid);

            tagStore.deleteTag(exist.getId());
        } catch (Exception excp) {
            LOG.error("deleteTagByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteTagByGuid({})", guid);
    }

    @GET
    @Path(TagRESTConstants.TAG_RESOURCE + "{id}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTag getTag(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.getTag({})", id);

        RangerTag ret;

        try {
            ret = tagStore.getTag(id);
        } catch (Exception excp) {
            LOG.error("getTag({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getTag({}): {}", id, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAG_RESOURCE + "guid/{guid}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTag getTagByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.getTagByGuid({})", guid);

        RangerTag ret;

        try {
            ret = tagStore.getTagByGuid(guid);
        } catch (Exception excp) {
            LOG.error("getTagByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getTagByGuid({}): {}", guid, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGS_RESOURCE + "type/{type}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public List<RangerTag> getTagsByType(@PathParam("type") String type) {
        LOG.debug("==> TagREST.getTagsByType({})", type);

        List<RangerTag> ret;

        try {
            ret = tagStore.getTagsByType(type);
        } catch (Exception excp) {
            LOG.error("getTagsByType({}) failed", type, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getTagsByType({}): {}", type, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGS_RESOURCE)
    @Produces("application/json")
    public List<RangerTag> getAllTags() {
        LOG.debug("==> TagREST.getAllTags()");

        // check for ADMIN access
        if (!bizUtil.isAdmin()) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_FORBIDDEN, "User don't have permission to perform this action", true);
        }

        List<RangerTag> ret;

        try {
            ret = tagStore.getTags(new SearchFilter());
        } catch (Exception excp) {
            LOG.error("getAllTags() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (CollectionUtils.isEmpty(ret)) {
            LOG.debug("getAllTags() - No tags found");
        }

        LOG.debug("<== TagREST.getAllTags(): {}", ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGS_RESOURCE_PAGINATED)
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public PList<RangerTag> getTags(@Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getTags()");

        final PList<RangerTag> ret;

        try {
            SearchFilter filter = searchUtil.getSearchFilter(request, tagService.sortFields);

            searchUtil.extractIntList(request, filter, SearchFilter.TAG_IDS, "Tag Id List");

            ret = tagStore.getPaginatedTags(filter);
        } catch (Exception excp) {
            LOG.error("getTags() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (CollectionUtils.isEmpty(ret.getList())) {
            LOG.debug("getTags() - No tags found");
        }

        LOG.debug("<== TagREST.getTags(): count={}", ret.getList() == null ? 0 : ret.getList().size());

        return ret;
    }

    /**
     * Resets/ removes tag policy cache for given service.
     *
     * @param serviceName non-empty service-name
     * @return {@code true} if successfully reseted/ removed for given service, {@code false} otherwise.
     */
    @GET
    @Path(TagRESTConstants.TAGS_RESOURCE + "cache/reset")
    @Produces("application/json")
    public boolean resetTagCache(@QueryParam("serviceName") String serviceName) {
        LOG.debug("==> TagREST.resetTagCache({})", serviceName);

        if (StringUtils.isEmpty(serviceName)) {
            throw restErrorUtil.createRESTException("Required parameter [serviceName] is missing.", MessageEnums.INVALID_INPUT_DATA);
        }

        RangerService rangerService = null;

        try {
            rangerService = svcStore.getServiceByName(serviceName);
        } catch (Exception e) {
            LOG.error("{} No Service Found for ServiceName: {}", HttpServletResponse.SC_BAD_REQUEST, serviceName);
        }

        if (rangerService == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, "Invalid service name", true);
        }

        // check for ADMIN access
        if (!bizUtil.isAdmin()) {
            boolean isServiceAdmin = false;
            String  loggedInUser   = bizUtil.getCurrentUserLoginId();

            try {
                isServiceAdmin = bizUtil.isUserServiceAdmin(rangerService, loggedInUser);
            } catch (Exception e) {
                LOG.warn("Failed to find if user [{}] has service admin privileges on service [{}]", loggedInUser, serviceName, e);
            }

            if (!isServiceAdmin) {
                throw restErrorUtil.createRESTException("User cannot reset tag cache", MessageEnums.OPER_NO_PERMISSION);
            }
        }

        boolean ret = tagStore.resetTagCache(serviceName);

        LOG.debug("<== TagREST.resetTagCache(): ret={}", ret);

        return ret;
    }

    /**
     * Resets/ removes tag policy cache for all.
     *
     * @return {@code true} if successfully reseted/ removed, {@code false} otherwise.
     */
    @GET
    @Path(TagRESTConstants.TAGS_RESOURCE + "cache/reset-all")
    @Produces("application/json")
    public boolean resetTagCacheAll() {
        LOG.debug("==> TagREST.resetTagCacheAll()");

        // check for ADMIN access
        if (!bizUtil.isAdmin()) {
            throw restErrorUtil.createRESTException("User cannot reset policy cache", MessageEnums.OPER_NO_PERMISSION);
        }

        boolean ret = tagStore.resetTagCache(null);

        LOG.debug("<== TagREST.resetTagCacheAll(): ret={}", ret);

        return ret;
    }

    @POST
    @Path(TagRESTConstants.RESOURCES_RESOURCE)
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource createServiceResource(RangerServiceResource resource, @DefaultValue("true") @QueryParam("updateIfExists") boolean updateIfExists) {
        LOG.debug("==> TagREST.createServiceResource({}, {})", resource, updateIfExists);

        RangerServiceResource ret;

        try {
            RangerServiceResource exist = validator.preCreateServiceResource(resource);

            if (exist == null) {
                ret = tagStore.createServiceResource(resource);
            } else if (updateIfExists) {
                ret = updateServiceResource(exist.getId(), resource);
            } else {
                throw new Exception("resource with Id " + exist.getId() + " already exists");
            }
        } catch (Exception excp) {
            LOG.error("createServiceResource({}) failed", resource, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.createServiceResource({}, {}): {}", resource, updateIfExists, ret);

        return ret;
    }

    @PUT
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "{id}")
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource updateServiceResource(@PathParam("id") Long id, RangerServiceResource resource) {
        LOG.debug("==> TagREST.updateServiceResource({})", id);

        RangerServiceResource ret;

        try {
            validator.preUpdateServiceResource(id, resource);

            ret = tagStore.updateServiceResource(resource);
        } catch (Exception excp) {
            LOG.error("updateServiceResource({}) failed", resource, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.updateServiceResource({}): {}", id, ret);

        return ret;
    }

    @PUT
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "guid/{guid}")
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource updateServiceResourceByGuid(@PathParam("guid") String guid, RangerServiceResource resource) {
        LOG.debug("==> TagREST.updateServiceResourceByGuid({}, {})", guid, resource);

        RangerServiceResource ret;

        try {
            validator.preUpdateServiceResourceByGuid(guid, resource);

            ret = tagStore.updateServiceResource(resource);
        } catch (Exception excp) {
            LOG.error("updateServiceResourceByGuid({}, {}) failed", guid, resource, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.updateServiceResourceByGuid({}, {}): {}", guid, resource, ret);

        return ret;
    }

    @DELETE
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "{id}")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteServiceResource(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.deleteServiceResource({})", id);

        try {
            validator.preDeleteServiceResource(id);
            tagStore.deleteServiceResource(id);
        } catch (Exception excp) {
            LOG.error("deleteServiceResource() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteServiceResource({})", id);
    }

    @DELETE
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "guid/{guid}")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteServiceResourceByGuid(@PathParam("guid") String guid, @DefaultValue("false") @QueryParam("deleteReferences") boolean deleteReferences) {
        LOG.debug("==> TagREST.deleteServiceResourceByGuid({}, {})", guid, deleteReferences);

        try {
            RangerServiceResource exist = validator.preDeleteServiceResourceByGuid(guid, deleteReferences);

            if (deleteReferences) {
                List<RangerTagResourceMap> tagResourceMaps = tagStore.getTagResourceMapsForResourceGuid(exist.getGuid());

                if (CollectionUtils.isNotEmpty(tagResourceMaps)) {
                    for (RangerTagResourceMap tagResourceMap : tagResourceMaps) {
                        deleteTagResourceMap(tagResourceMap.getId());
                    }
                }
            }

            tagStore.deleteServiceResource(exist.getId());
        } catch (Exception excp) {
            LOG.error("deleteServiceResourceByGuid({}, {}) failed", guid, deleteReferences, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteServiceResourceByGuid({}, {})", guid, deleteReferences);
    }

    @GET
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "{id}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource getServiceResource(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.getServiceResource({})", id);

        RangerServiceResource ret;

        try {
            ret = tagStore.getServiceResource(id);
        } catch (Exception excp) {
            LOG.error("getServiceResource({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getServiceResource({}): {}", id, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "guid/{guid}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource getServiceResourceByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.getServiceResourceByGuid({})", guid);

        RangerServiceResource ret;

        try {
            ret = tagStore.getServiceResourceByGuid(guid);
        } catch (Exception excp) {
            LOG.error("getServiceResourceByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getServiceResourceByGuid({}): {}", guid, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.RESOURCES_RESOURCE + "service/{serviceName}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public List<RangerServiceResource> getServiceResourcesByService(@PathParam("serviceName") String serviceName) {
        LOG.debug("==> TagREST.getServiceResourcesByService({})", serviceName);

        List<RangerServiceResource> ret;

        try {
            ret = tagStore.getServiceResourcesByService(serviceName);
        } catch (Exception excp) {
            LOG.error("getServiceResourcesByService({}) failed", serviceName, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (CollectionUtils.isEmpty(ret)) {
            LOG.debug("getServiceResourcesByService({}) - No service-resources found", serviceName);
        }
        LOG.debug("<== TagREST.getServiceResourcesByService({}): count={}", serviceName, (ret == null ? 0 : ret.size()));

        return ret;
    }

    @GET
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "service/{serviceName}/signature/{resourceSignature}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource getServiceResourceByServiceAndResourceSignature(@PathParam("serviceName") String serviceName, @PathParam("resourceSignature") String resourceSignature) {
        LOG.debug("==> TagREST.getServiceResourceByServiceAndResourceSignature({}, {})", serviceName, resourceSignature);

        RangerServiceResource ret;

        try {
            ret = tagStore.getServiceResourceByServiceAndResourceSignature(serviceName, resourceSignature);
        } catch (Exception excp) {
            LOG.error("getServiceResourceByServiceAndResourceSignature({}, {})", serviceName, resourceSignature, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getServiceResourceByServiceAndResourceSignature({}, {}): {}", serviceName, resourceSignature, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.RESOURCE_RESOURCE + "service/{serviceName}/resource")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResource getServiceResourceByResource(@PathParam("serviceName") String serviceName, @Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getServiceResourceByResource({})", serviceName);

        Map<String, String[]> resourceMap     = searchUtil.getMultiValueParamsWithPrefix(request, SearchFilter.RESOURCE_PREFIX, true);
        RangerServiceResource serviceResource = TagDBStore.toRangerServiceResource(serviceName, resourceMap);

        serviceResource = getServiceResourceByServiceAndResourceSignature(serviceName, new RangerServiceResourceSignature(serviceResource).getSignature());

        LOG.debug("<== TagREST.getServiceResourceByResource(serviceName=[{}] RangerServiceResource=[{}])", serviceName, serviceResource);

        return serviceResource;
    }

    @GET
    @Path(TagRESTConstants.RESOURCES_RESOURCE)
    @Produces("application/json")
    public List<RangerServiceResource> getAllServiceResources() {
        LOG.debug("==> TagREST.getAllServiceResources()");

        // check for ADMIN access
        if (!bizUtil.isAdmin()) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_FORBIDDEN, "User don't have permission to perform this action", true);
        }

        List<RangerServiceResource> ret;

        try {
            ret = tagStore.getServiceResources(new SearchFilter());
        } catch (Exception excp) {
            LOG.error("getAllServiceResources() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getAllServiceResources(): count={}", (ret == null ? 0 : ret.size()));

        return ret;
    }

    @GET
    @Path(TagRESTConstants.RESOURCES_RESOURCE_PAGINATED)
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerServiceResourceWithTagsList getServiceResourcesWithTags(@Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getServiceResources()");

        RangerServiceResourceWithTagsList ret;

        try {
            SearchFilter filter = searchUtil.getSearchFilter(request, rangerServiceResourceWithTagsService.sortFields);

            searchUtil.extractIntList(request, filter, SearchFilter.TAG_RESOURCE_IDS, "Tag resource list");
            searchUtil.extractStringList(request, filter, SearchFilter.TAG_NAMES, "Tag type List", "tagTypes", null, null);

            ret = tagStore.getPaginatedServiceResourcesWithTags(filter);
        } catch (Exception excp) {
            LOG.error("getServiceResources() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getServiceResources(): count={}", ((ret == null || ret.getList() == null) ? 0 : ret.getList().size()));

        return ret;
    }

    @POST
    @Path(TagRESTConstants.TAGRESOURCEMAPS_RESOURCE)
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagResourceMap createTagResourceMap(@QueryParam("tag-guid") String tagGuid, @QueryParam("resource-guid") String resourceGuid, @DefaultValue("false") @QueryParam("lenient") boolean lenient) {
        LOG.debug("==> TagREST.createTagResourceMap({}, {}, {})", tagGuid, resourceGuid, lenient);

        RangerTagResourceMap tagResourceMap;

        try {
            tagResourceMap = tagStore.getTagResourceMapForTagAndResourceGuid(tagGuid, resourceGuid);

            if (tagResourceMap == null) {
                tagResourceMap = validator.preCreateTagResourceMap(tagGuid, resourceGuid);

                tagResourceMap = tagStore.createTagResourceMap(tagResourceMap);
            } else if (!lenient) {
                throw new Exception("tagResourceMap with tag-guid=" + tagGuid + " and resource-guid=" + resourceGuid + " already exists");
            }
        } catch (Exception excp) {
            LOG.error("createTagResourceMap({}, {}, {})", tagGuid, resourceGuid, lenient, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("==> TagREST.createTagResourceMap({}, {}, {})", tagGuid, resourceGuid, lenient);

        return tagResourceMap;
    }

    @DELETE
    @Path(TagRESTConstants.TAGRESOURCEMAP_RESOURCE + "{id}")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagResourceMap(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.deleteTagResourceMap({})", id);

        try {
            validator.preDeleteTagResourceMap(id);
            tagStore.deleteTagResourceMap(id);
        } catch (Exception excp) {
            LOG.error("deleteTagResourceMap() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteTagResourceMap({})", id);
    }

    @DELETE
    @Path(TagRESTConstants.TAGRESOURCEMAP_RESOURCE + "guid/{guid}")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagResourceMapByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.deleteTagResourceMapByGuid({})", guid);

        try {
            RangerTagResourceMap exist = validator.preDeleteTagResourceMapByGuid(guid);

            tagStore.deleteTagResourceMap(exist.getId());
        } catch (Exception excp) {
            LOG.error("deleteTagResourceMapByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.deleteTagResourceMapByGuid({})", guid);
    }

    @DELETE
    @Path(TagRESTConstants.TAGRESOURCEMAPS_RESOURCE)
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagResourceMap(@QueryParam("tag-guid") String tagGuid, @QueryParam("resource-guid") String resourceGuid) {
        LOG.debug("==> TagREST.deleteTagResourceMap({}, {})", tagGuid, resourceGuid);

        try {
            RangerTagResourceMap exist = validator.preDeleteTagResourceMap(tagGuid, resourceGuid);

            tagStore.deleteTagResourceMap(exist.getId());
        } catch (Exception excp) {
            LOG.error("deleteTagResourceMap({}, {}) failed", tagGuid, resourceGuid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("==> TagREST.deleteTagResourceMap({}, {})", tagGuid, resourceGuid);
    }

    @GET
    @Path(TagRESTConstants.TAGRESOURCEMAP_RESOURCE + "{id}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagResourceMap getTagResourceMap(@PathParam("id") Long id) {
        LOG.debug("==> TagREST.getTagResourceMap({})", id);
        RangerTagResourceMap ret;

        try {
            ret = tagStore.getTagResourceMap(id);
        } catch (Exception excp) {
            LOG.error("getTagResourceMap({}) failed", id, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getTagResourceMap({}): {}", id, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGRESOURCEMAP_RESOURCE + "guid/{guid}")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagResourceMap getTagResourceMapByGuid(@PathParam("guid") String guid) {
        LOG.debug("==> TagREST.getTagResourceMapByGuid({})", guid);
        RangerTagResourceMap ret;

        try {
            ret = tagStore.getTagResourceMapByGuid(guid);
        } catch (Exception excp) {
            LOG.error("getTagResourceMapByGuid({}) failed", guid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("<== TagREST.getTagResourceMapByGuid({}): {}", guid, ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGRESOURCEMAP_RESOURCE + "tag-resource-guid")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public RangerTagResourceMap getTagResourceMap(@QueryParam("tagGuid") String tagGuid, @QueryParam("resourceGuid") String resourceGuid) {
        LOG.debug("==> TagREST.getTagResourceMap({}, {})", tagGuid, resourceGuid);

        RangerTagResourceMap ret;

        try {
            ret = tagStore.getTagResourceMapForTagAndResourceGuid(tagGuid, resourceGuid);
        } catch (Exception excp) {
            LOG.error("getTagResourceMap({}, {}) failed", tagGuid, resourceGuid, excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        LOG.debug("==> TagREST.getTagResourceMap({}, {})", tagGuid, resourceGuid);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGRESOURCEMAPS_RESOURCE)
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public List<RangerTagResourceMap> getAllTagResourceMaps() {
        LOG.debug("==> TagREST.getAllTagResourceMaps()");

        List<RangerTagResourceMap> ret;

        try {
            ret = tagStore.getTagResourceMaps(new SearchFilter());
        } catch (Exception excp) {
            LOG.error("getAllTagResourceMaps() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (CollectionUtils.isEmpty(ret)) {
            LOG.debug("getAllTagResourceMaps() - No tag-resource-maps found");
        }
        LOG.debug("<== TagREST.getAllTagResourceMaps(): {}", ret);

        return ret;
    }

    @GET
    @Path(TagRESTConstants.TAGRESOURCEMAPS_RESOURCE_PAGINATED)
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public PList<RangerTagResourceMap> getTagResourceMaps(@Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getTagResourceMaps()");

        final PList<RangerTagResourceMap> ret;

        try {
            SearchFilter filter = searchUtil.getSearchFilter(request, rangerTagResourceMapService.sortFields);

            ret = tagStore.getPaginatedTagResourceMaps(filter);
        } catch (Exception excp) {
            LOG.error("getTagResourceMaps() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        }

        if (ret == null) {
            throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Not found", true);
        }

        LOG.debug("<== TagREST.getTagResourceMaps(): {}", ret);

        return ret;
    }

    @PUT
    @Path(TagRESTConstants.IMPORT_SERVICETAGS_RESOURCE)
    @Consumes("application/json")
    @Produces("application/json")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void importServiceTags(ServiceTags serviceTags) {
        LOG.debug("==> TagREST.importServiceTags()");

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_LOG, "TagREST.importServiceTags(service=" + (serviceTags != null ? serviceTags.getServiceName() : null) + ")");
        }

        try {
            ServiceTagsProcessor serviceTagsProcessor = new ServiceTagsProcessor(tagStore);

            serviceTagsProcessor.process(serviceTags);
        } catch (Exception excp) {
            LOG.error("importServiceTags() failed", excp);

            throw restErrorUtil.createRESTException(HttpServletResponse.SC_BAD_REQUEST, excp.getMessage(), true);
        } finally {
            RangerPerfTracer.log(perf);
        }

        LOG.debug("<== TagREST.importServiceTags()");
    }

    // This API is used by tag-sync to upload tag-objects

    @GET
    @Path(TagRESTConstants.TAGS_DOWNLOAD + "{serviceName}")
    @Produces("application/json")
    public ServiceTags getServiceTagsIfUpdated(@PathParam("serviceName") String serviceName, @QueryParam(TagRESTConstants.LAST_KNOWN_TAG_VERSION_PARAM) Long lastKnownVersion, @DefaultValue("0") @QueryParam(TagRESTConstants.LAST_ACTIVATION_TIME) Long lastActivationTime, @QueryParam("pluginId") String pluginId, @DefaultValue("false") @QueryParam(RangerRESTUtils.REST_PARAM_SUPPORTS_TAG_DELTAS) Boolean supportsTagDeltas, @DefaultValue("") @QueryParam(RangerRESTUtils.REST_PARAM_CAPABILITIES) String pluginCapabilities, @Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getServiceTagsIfUpdated({}, {}, {}, {}, {})", serviceName, lastKnownVersion, lastActivationTime, pluginId, supportsTagDeltas);

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_LOG, "TagREST.getServiceTagsIfUpdated(service=" + serviceName + ", lastKnownVersion=" + lastKnownVersion + ")");
        }

        ServiceTags ret               = null;
        int         httpCode          = HttpServletResponse.SC_OK;
        Long        downloadedVersion = null;
        String      clusterName       = null;
        String      logMsg;

        if (request != null) {
            clusterName = !StringUtils.isEmpty(request.getParameter(SearchFilter.CLUSTER_NAME)) ? request.getParameter(SearchFilter.CLUSTER_NAME) : "";
        }

        try {
            bizUtil.failUnauthenticatedDownloadIfNotAllowed();

            ret = tagStore.getServiceTagsIfUpdated(serviceName, lastKnownVersion, !supportsTagDeltas);

            if (ret == null) {
                downloadedVersion = lastKnownVersion;
                httpCode          = HttpServletResponse.SC_NOT_MODIFIED;
                logMsg            = "No change since last update";
            } else {
                downloadedVersion = ret.getTagVersion();
                logMsg            = "Returning " + (ret.getTags() != null ? ret.getTags().size() : 0) + " tags. Tag version=" + ret.getTagVersion();
            }
        } catch (WebApplicationException webException) {
            httpCode = webException.getResponse().getStatus();
            logMsg   = webException.getResponse().getEntity().toString();
        } catch (Exception excp) {
            httpCode = HttpServletResponse.SC_BAD_REQUEST;
            logMsg   = excp.getMessage();
        } finally {
            assetMgr.createPluginInfo(serviceName, pluginId, request, RangerPluginInfo.ENTITY_TYPE_TAGS, downloadedVersion, lastKnownVersion, lastActivationTime, httpCode, clusterName, pluginCapabilities);

            RangerPerfTracer.log(perf);
        }

        if (httpCode != HttpServletResponse.SC_OK) {
            boolean logError = httpCode != HttpServletResponse.SC_NOT_MODIFIED;

            throw restErrorUtil.createRESTException(httpCode, logMsg, logError);
        }

        LOG.debug("<== TagREST.getServiceTagsIfUpdated({}, {}, {}, {}, {})", serviceName, lastKnownVersion, lastActivationTime, pluginId, supportsTagDeltas);

        return ret;
    }

    // This API is typically used by plug-in to get selected tagged resources from RangerAdmin

    @GET
    @Path(TagRESTConstants.TAGS_SECURE_DOWNLOAD + "{serviceName}")
    @Produces("application/json")
    public ServiceTags getSecureServiceTagsIfUpdated(@PathParam("serviceName") String serviceName, @QueryParam(TagRESTConstants.LAST_KNOWN_TAG_VERSION_PARAM) Long lastKnownVersion, @DefaultValue("0") @QueryParam(TagRESTConstants.LAST_ACTIVATION_TIME) Long lastActivationTime, @QueryParam("pluginId") String pluginId, @DefaultValue("false") @QueryParam(RangerRESTUtils.REST_PARAM_SUPPORTS_TAG_DELTAS) Boolean supportsTagDeltas, @DefaultValue("") @QueryParam(RangerRESTUtils.REST_PARAM_CAPABILITIES) String pluginCapabilities, @Context HttpServletRequest request) {
        LOG.debug("==> TagREST.getSecureServiceTagsIfUpdated({}, {}, {}, {}, {})", serviceName, lastKnownVersion, lastActivationTime, pluginId, supportsTagDeltas);

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_LOG, "TagREST.getSecureServiceTagsIfUpdated(service=" + serviceName + ", lastKnownVersion=" + lastKnownVersion + ")");
        }

        ServiceTags ret               = null;
        int         httpCode          = HttpServletResponse.SC_OK;
        boolean     isAdmin           = bizUtil.isAdmin();
        boolean     isKeyAdmin        = bizUtil.isKeyAdmin();
        Long        downloadedVersion = null;
        String      clusterName       = null;
        String      logMsg;
        boolean     isAllowed;

        if (request != null) {
            clusterName = !StringUtils.isEmpty(request.getParameter(SearchFilter.CLUSTER_NAME)) ? request.getParameter(SearchFilter.CLUSTER_NAME) : "";
        }

        try {
            XXService xService = daoManager.getXXService().findByName(serviceName);

            if (xService == null) {
                LOG.error("Requested Service not found. serviceName={}", serviceName);

                throw restErrorUtil.createRESTException(HttpServletResponse.SC_NOT_FOUND, "Service:" + serviceName + " not found", false);
            }

            XXServiceDef  xServiceDef   = daoManager.getXXServiceDef().getById(xService.getType());
            RangerService rangerService = svcStore.getServiceByName(serviceName);

            if (StringUtils.equals(xServiceDef.getImplclassname(), EmbeddedServiceDefsUtil.KMS_IMPL_CLASS_NAME)) {
                if (isKeyAdmin) {
                    isAllowed = true;
                } else {
                    isAllowed = bizUtil.isUserAllowed(rangerService, Allowed_User_List_For_Tag_Download);
                }
            } else {
                if (isAdmin) {
                    isAllowed = true;
                } else {
                    isAllowed = bizUtil.isUserAllowed(rangerService, Allowed_User_List_For_Tag_Download);
                }
            }
            if (isAllowed) {
                ret = tagStore.getServiceTagsIfUpdated(serviceName, lastKnownVersion, !supportsTagDeltas);

                if (ret == null) {
                    downloadedVersion = lastKnownVersion;
                    httpCode          = HttpServletResponse.SC_NOT_MODIFIED;
                    logMsg            = "No change since last update";
                } else {
                    downloadedVersion = ret.getTagVersion();
                    logMsg            = "Returning " + (ret.getTags() != null ? ret.getTags().size() : 0) + " tags. Tag version=" + ret.getTagVersion();
                }
            } else {
                LOG.error("getSecureServiceTagsIfUpdated({}, {}, {}) failed as User doesn't have permission to download tags", serviceName, lastKnownVersion, lastActivationTime);

                httpCode = HttpServletResponse.SC_FORBIDDEN; // assert user is authenticated.
                logMsg   = "User doesn't have permission to download tags";
            }
        } catch (WebApplicationException webException) {
            httpCode = webException.getResponse().getStatus();
            logMsg   = webException.getResponse().getEntity().toString();
        } catch (Exception excp) {
            httpCode = HttpServletResponse.SC_BAD_REQUEST;
            logMsg   = excp.getMessage();
        } finally {
            assetMgr.createPluginInfo(serviceName, pluginId, request, RangerPluginInfo.ENTITY_TYPE_TAGS, downloadedVersion, lastKnownVersion, lastActivationTime, httpCode, clusterName, pluginCapabilities);

            RangerPerfTracer.log(perf);
        }

        if (httpCode != HttpServletResponse.SC_OK) {
            boolean logError = httpCode != HttpServletResponse.SC_NOT_MODIFIED;

            throw restErrorUtil.createRESTException(httpCode, logMsg, logError);
        }

        LOG.debug("<== TagREST.getSecureServiceTagsIfUpdated({}, {}, {}, {}, {})", serviceName, lastKnownVersion, lastActivationTime, pluginId, supportsTagDeltas);

        return ret;
    }

    @DELETE
    @Path("/server/tagdeltas")
    @PreAuthorize("hasRole('ROLE_SYS_ADMIN')")
    public void deleteTagDeltas(@DefaultValue("3") @QueryParam("days") Integer olderThan, @Context HttpServletRequest request) {
        LOG.debug("==> ServiceREST.deleteTagDeltas({})", olderThan);

        svcStore.resetTagUpdateLog(olderThan, ServiceTags.TagsChangeType.INVALIDATE_TAG_DELTAS);

        LOG.debug("<== ServiceREST.deleteTagDeltas({})", olderThan);
    }

    TagStore getTagStore() {
        return tagStore;
    }
}
