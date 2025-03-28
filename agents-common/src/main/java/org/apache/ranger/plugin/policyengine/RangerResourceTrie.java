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

package org.apache.ranger.plugin.policyengine;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.Predicate;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.ranger.plugin.model.RangerPolicy.RangerPolicyResource;
import org.apache.ranger.plugin.model.RangerServiceDef.RangerResourceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest.ResourceElementMatchingScope;
import org.apache.ranger.plugin.policyevaluator.RangerPolicyEvaluator;
import org.apache.ranger.plugin.policyresourcematcher.RangerResourceEvaluator;
import org.apache.ranger.plugin.resourcematcher.RangerAbstractResourceMatcher;
import org.apache.ranger.plugin.resourcematcher.RangerResourceMatcher;
import org.apache.ranger.plugin.util.RangerPerfTracer;
import org.apache.ranger.plugin.util.RangerRequestExprResolver;
import org.apache.ranger.plugin.util.ServiceDefUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.apache.ranger.plugin.resourcematcher.RangerPathResourceMatcher.DEFAULT_PATH_SEPARATOR_CHAR;
import static org.apache.ranger.plugin.resourcematcher.RangerPathResourceMatcher.OPTION_PATH_SEPARATOR;

public class RangerResourceTrie<T extends RangerResourceEvaluator> {
    private static final Logger LOG                = LoggerFactory.getLogger(RangerResourceTrie.class);
    private static final Logger TRACE_LOG          = RangerPerfTracer.getPerfLogger("resourcetrie.trace");
    private static final Logger PERF_TRIE_INIT_LOG = RangerPerfTracer.getPerfLogger("resourcetrie.init");
    private static final Logger PERF_TRIE_OP_LOG   = RangerPerfTracer.getPerfLogger("resourcetrie.op");

    private static final String DEFAULT_WILDCARD_CHARS    = "*?";
    private static final String TRIE_BUILDER_THREAD_COUNT = "ranger.policyengine.trie.builder.thread.count";

    private final RangerResourceDef resourceDef;
    private final boolean           optIgnoreCase;
    private final boolean           optWildcard;
    private final String            wildcardChars;
    private final boolean           isOptimizedForRetrieval;
    private final boolean           isOptimizedForSpace;
    private final Character         separatorChar;
    private final TrieNode<T>       root;
    private       Set<T>            inheritedEvaluators;

    public RangerResourceTrie(RangerResourceDef resourceDef, List<T> evaluators) {
        this(resourceDef, evaluators, true, null);
    }

    public RangerResourceTrie(RangerResourceTrie<T> other) {
        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_INIT_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_INIT_LOG, "RangerResourceTrie.copyTrie(name=" + other.resourceDef.getName() + ")");
        }

        this.resourceDef             = other.resourceDef;
        this.optIgnoreCase           = other.optIgnoreCase;
        this.optWildcard             = other.optWildcard;
        this.wildcardChars           = other.wildcardChars;
        this.isOptimizedForSpace     = other.isOptimizedForSpace;
        this.isOptimizedForRetrieval = other.isOptimizedForRetrieval;
        this.separatorChar           = other.separatorChar;
        this.inheritedEvaluators     = other.inheritedEvaluators != null ? new HashSet<>(other.inheritedEvaluators) : null;
        this.root                    = copyTrieSubtree(other.root, null);

        wrapUpUpdate();

        if (!isOptimizedForRetrieval) {
            LOG.debug("Trie for {} is not optimized for retrieval. Resetting isSetup flag by calling undoSetup() on the root", this.resourceDef.getName());

            root.undoSetup();
        }

        RangerPerfTracer.logAlways(perf);

        if (PERF_TRIE_INIT_LOG.isDebugEnabled()) {
            PERF_TRIE_INIT_LOG.debug(toString());
        }

        if (TRACE_LOG.isTraceEnabled()) {
            TRACE_LOG.trace("Trie Dump from RangerResourceTrie.copyTrie(name={}):\n[{}]", other.resourceDef.getName(), dumpTrie());
        }
    }

    public RangerResourceTrie(RangerResourceDef resourceDef, List<T> evaluators, boolean isOptimizedForRetrieval, RangerPluginContext pluginContext) {
        this(resourceDef, evaluators, isOptimizedForRetrieval, false, pluginContext);
    }

    public <E> RangerResourceTrie(RangerResourceDef resourceDef, List<E> evaluators, boolean isOptimizedForRetrieval, boolean isOptimizedForSpace, RangerPluginContext pluginContext) {
        LOG.debug("==> RangerResourceTrie({}, evaluatorCount={}, isOptimizedForRetrieval={}, isOptimizedForSpace={})", resourceDef.getName(), evaluators.size(), isOptimizedForRetrieval, isOptimizedForSpace);

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_INIT_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_INIT_LOG, "RangerResourceTrie.init(name=" + resourceDef.getName() + ")");
        }

        Configuration config             = pluginContext != null ? pluginContext.getConfig() : null;
        int           builderThreadCount = config != null ? config.getInt(TRIE_BUILDER_THREAD_COUNT, 1) : 1;

        if (builderThreadCount < 1) {
            builderThreadCount = 1;
        }

        if (TRACE_LOG.isTraceEnabled()) {
            TRACE_LOG.trace("builderThreadCount is set to [{}]", builderThreadCount);
        }

        Map<String, String> matcherOptions           = resourceDef.getMatcherOptions();
        boolean             optReplaceTokens         = RangerAbstractResourceMatcher.getOptionReplaceTokens(matcherOptions);
        boolean             optReplaceReqExpressions = RangerAbstractResourceMatcher.getOptionReplaceReqExpressions(matcherOptions);
        String              tokenReplaceSpecialChars = "";

        if (optReplaceTokens) {
            char delimiterStart  = RangerAbstractResourceMatcher.getOptionDelimiterStart(matcherOptions);
            char delimiterEnd    = RangerAbstractResourceMatcher.getOptionDelimiterEnd(matcherOptions);
            char delimiterEscape = RangerAbstractResourceMatcher.getOptionDelimiterEscape(matcherOptions);

            tokenReplaceSpecialChars += delimiterStart;
            tokenReplaceSpecialChars += delimiterEnd;
            tokenReplaceSpecialChars += delimiterEscape;
        }

        if (optReplaceReqExpressions) {
            tokenReplaceSpecialChars += RangerRequestExprResolver.EXPRESSION_START.charAt(0);
        }

        this.resourceDef             = resourceDef;
        this.optIgnoreCase           = RangerAbstractResourceMatcher.getOptionIgnoreCase(matcherOptions);
        this.optWildcard             = RangerAbstractResourceMatcher.getOptionWildCard(matcherOptions);
        this.wildcardChars           = optWildcard ? DEFAULT_WILDCARD_CHARS + tokenReplaceSpecialChars : tokenReplaceSpecialChars;
        this.isOptimizedForSpace     = isOptimizedForSpace;
        this.isOptimizedForRetrieval = !isOptimizedForSpace && isOptimizedForRetrieval;  // isOptimizedForSpace takes precedence
        this.separatorChar           = ServiceDefUtil.getCharOption(matcherOptions, OPTION_PATH_SEPARATOR, DEFAULT_PATH_SEPARATOR_CHAR);

        final TrieNode<T> tmpRoot = buildTrie(resourceDef, evaluators, builderThreadCount);

        if (builderThreadCount > 1 && tmpRoot == null) { // if multithreaded trie-creation failed, build using a single thread
            this.root = buildTrie(resourceDef, evaluators, 1);
        } else {
            this.root = tmpRoot;
        }

        wrapUpUpdate();

        RangerPerfTracer.logAlways(perf);

        if (PERF_TRIE_INIT_LOG.isDebugEnabled()) {
            PERF_TRIE_INIT_LOG.debug(toString());
        }

        if (TRACE_LOG.isTraceEnabled()) {
            TRACE_LOG.trace("Trie Dump from RangerResourceTrie.init(name={}):\n[{}]", resourceDef.getName(), dumpTrie());
        }

        LOG.debug("<== RangerResourceTrie({}, evaluatorCount={}, isOptimizedForRetrieval={}, isOptimizedForSpace={}): {}", resourceDef.getName(), evaluators.size(), this.isOptimizedForRetrieval, this.isOptimizedForSpace, this);
    }

    public Set<T> getEvaluatorsForResource(Object resource) {
        return getEvaluatorsForResource(resource, ResourceElementMatchingScope.SELF);
    }

    public Set<T> getEvaluatorsForResource(Object resource, ResourceElementMatchingScope scope) {
        return getEvaluatorsForResource(resource, scope, (Predicate) null);
    }

    public Set<T> getEvaluatorsForResource(Object resource, ResourceElementMatchingScope scope, Predicate predicate) {
        EvalCollector<T> ret = new EvalCollector<>(predicate);

        traverse(resource, scope, ret);

        return ret.getResult();
    }

    public Set<T> getEvaluatorsForResource(Object resource, ResourceElementMatchingScope scope, Set<T> filter) {
        return getEvaluatorsForResource(resource, scope, filter, null);
    }

    public Set<T> getEvaluatorsForResource(Object resource, ResourceElementMatchingScope scope, Set<T> filter, Predicate predicate) {
        EvalSubsetCollector<T> ret = new EvalSubsetCollector<>(filter, predicate);

        traverse(resource, scope, ret);

        return ret.getResult();
    }

    public int getEvaluatorsCountForResource(Object resource, ResourceElementMatchingScope scope) {
        return getEvaluatorsCountForResource(resource, scope, null);
    }

    public int getEvaluatorsCountForResource(Object resource, ResourceElementMatchingScope scope, Predicate predicate) {
        EvalCountCollector<T> ret = new EvalCountCollector<>(predicate);

        traverse(resource, scope, ret);

        return ret.getResult();
    }

    public void add(RangerPolicyResource resource, T evaluator) {
        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_INIT_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_INIT_LOG, "RangerResourceTrie.add(name=" + resource + ")");
        }

        if (resource == null) {
            if (evaluator.isAncestorOf(resourceDef)) {
                addInheritedEvaluator(evaluator);
            }
        } else {
            if (resource.getIsExcludes()) {
                addInheritedEvaluator(evaluator);
            } else {
                if (CollectionUtils.isNotEmpty(resource.getValues())) {
                    for (String value : resource.getValues()) {
                        insert(root, value, resource.getIsRecursive(), evaluator);
                    }
                }
            }
        }

        RangerPerfTracer.logAlways(perf);

        if (TRACE_LOG.isTraceEnabled()) {
            TRACE_LOG.trace("Trie Dump from RangerResourceTrie.add(name={}):\n[{}]", resource, dumpTrie());
        }
    }

    public void delete(RangerPolicyResource resource, T evaluator) {
        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_INIT_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_INIT_LOG, "RangerResourceTrie.delete(name=" + resource + ")");
        }

        if (resource == null) {
            if (evaluator.isAncestorOf(resourceDef)) {
                removeInheritedEvaluator(evaluator);
            }
        } else if (resource.getIsExcludes()) {
            removeInheritedEvaluator(evaluator);
        } else {
            for (String value : resource.getValues()) {
                TrieNode<T> node = getNodeForResource(value);

                if (node != null) {
                    node.removeEvaluatorFromSubtree(evaluator);
                }
            }
        }

        RangerPerfTracer.logAlways(perf);

        if (TRACE_LOG.isTraceEnabled()) {
            TRACE_LOG.trace("Trie Dump from RangerResourceTrie.delete(name={}):\n[{}]", resource, dumpTrie());
        }
    }

    public void wrapUpUpdate() {
        if (root != null) {
            root.wrapUpUpdate();

            if (TRACE_LOG.isTraceEnabled()) {
                TRACE_LOG.trace("Trie Dump from RangerResourceTrie.wrapUpUpdate(name={}):\n[{}]", resourceDef.getName(), dumpTrie());
            }
        }
    }

    public StringBuilder dumpTrie() {
        StringBuilder sb = new StringBuilder();
        if (root != null) {
            root.toString("", sb);
        }
        return sb;
    }

    public void traverse(Object resource, ResourceElementMatchingScope scope, TraverseMatchHandler<T> handler) {
        if (resource instanceof String) {
            traverse((String) resource, scope, handler);
        } else if (resource instanceof Collection) {
            Collection<String> resources = (Collection<String>) resource;

            if (CollectionUtils.isEmpty(resources)) {  // treat empty collection same as empty-string
                traverse("", scope, handler);
            } else {
                traverse(resources, scope, handler);
            }
        }
    }

    public void traverse(Collection<String> resources, ResourceElementMatchingScope scope, TraverseMatchHandler<T> handler) {
        for (String resource : resources) {
            traverse(resource, scope, handler);
        }
    }

    public void traverse(String resource, ResourceElementMatchingScope scope, TraverseMatchHandler<T> handler) {
        LOG.debug("==> RangerResourceTrie.traverse({}, {})", resource, scope);

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_OP_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_OP_LOG, "RangerResourceTrie.traverse(resource=" + resource + ")");
        }

        TrieNode<T> curr   = root;
        TrieNode<T> parent = null;
        TrieNode<T> child  = null;
        final int   len    = resource.length();
        int         i      = 0;

        handler.process(inheritedEvaluators);

        while (i < len) {
            if (!isOptimizedForSpace) {
                curr.setupIfNeeded(parent);
            } else {
                if (handler.process(curr.getWildcardEvaluators())) {
                    break;
                }
            }

            child = curr.getChild(getLookupChar(resource, i));

            if (child == null) {
                break;
            }

            final String childStr = child.getStr();

            if (!resource.regionMatches(optIgnoreCase, i, childStr, 0, childStr.length())) {
                break;
            }

            parent = curr;
            curr   = child;
            i += childStr.length();
        }

        if (!isOptimizedForSpace) {
            curr.setupIfNeeded(parent);
        } else {
            handler.process(curr.getWildcardEvaluators());
        }

        boolean isSelfMatch = (i == len);

        if (!isOptimizedForSpace) {
            handler.process(isSelfMatch ? curr.getEvaluators() : curr.getWildcardEvaluators());
        } else {
            if (isSelfMatch) {
                handler.process(curr.getEvaluators());
            }
        }

        if (scope == ResourceElementMatchingScope.SELF_OR_CHILD) {
            final boolean resourceEndsWithSep = resource.charAt(resource.length() - 1) == separatorChar;

            if (isSelfMatch) { // resource == path(curr)
                if (resourceEndsWithSep) { // ex: resource=/tmp/
                    curr.getChildren().values().forEach(c -> c.collectChildEvaluators(separatorChar, 0, handler));
                } else { // ex: resource=/tmp
                    curr = curr.getChild(separatorChar);

                    if (curr != null) {
                        curr.collectChildEvaluators(separatorChar, 1, handler);
                    }
                }
            } else if (child != null) { // resource != path(child) ex: (resource=/tmp, path(child)=/tmp/test.txt or path(child)=/tmpdir)
                int     remainingLen  = len - i;
                boolean isPrefixMatch = child.getStr().regionMatches(optIgnoreCase, 0, resource, i, remainingLen);

                if (isPrefixMatch) {
                    if (resourceEndsWithSep) { // ex: resource=/tmp/
                        child.collectChildEvaluators(separatorChar, remainingLen, handler);
                    } else if (child.getStr().charAt(remainingLen) == separatorChar) { //  ex: resource=/tmp
                        child.collectChildEvaluators(separatorChar, remainingLen + 1, handler);
                    }
                }
            }
        } else if (scope == ResourceElementMatchingScope.SELF_OR_PREFIX) {
            curr.collectChildEvaluators(resource, i, handler);
        }

        RangerPerfTracer.logAlways(perf);

        LOG.debug("<== RangerResourceTrie.traverse({}, {})", resource, scope);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        TrieData trieData = getTrieData();

        sb.append("resourceName=").append(resourceDef.getName());
        sb.append("; optIgnoreCase=").append(optIgnoreCase);
        sb.append("; optWildcard=").append(optWildcard);
        sb.append("; wildcardChars=").append(wildcardChars);
        sb.append("; nodeCount=").append(trieData.nodeCount);
        sb.append("; leafNodeCount=").append(trieData.leafNodeCount);
        sb.append("; singleChildNodeCount=").append(trieData.singleChildNodeCount);
        sb.append("; maxDepth=").append(trieData.maxDepth);
        sb.append("; evaluatorListCount=").append(trieData.evaluatorListCount);
        sb.append("; wildcardEvaluatorListCount=").append(trieData.wildcardEvaluatorListCount);
        sb.append("; evaluatorListRefCount=").append(trieData.evaluatorListRefCount);
        sb.append("; wildcardEvaluatorListRefCount=").append(trieData.wildcardEvaluatorListRefCount);

        return sb.toString();
    }

    TrieNode<T> getRoot() {
        return root;
    }

    private void addInheritedEvaluator(T evaluator) {
        if (inheritedEvaluators == null) {
            inheritedEvaluators = new HashSet<>();
        }

        inheritedEvaluators.add(evaluator);
    }

    private void removeInheritedEvaluator(T evaluator) {
        if (CollectionUtils.isNotEmpty(inheritedEvaluators) && inheritedEvaluators.contains(evaluator)) {
            inheritedEvaluators.remove(evaluator);

            if (CollectionUtils.isEmpty(inheritedEvaluators)) {
                inheritedEvaluators = null;
            }
        }
    }

    private TrieNode<T> copyTrieSubtree(final TrieNode<T> source, final TrieNode<T> parent) {
        if (TRACE_LOG.isTraceEnabled()) {
            StringBuilder sb = new StringBuilder();

            source.toString(sb);

            TRACE_LOG.trace("==> copyTrieSubtree({})", sb);
        }

        TrieNode<T> dest = new TrieNode<>(source.str);

        if (parent != null) {
            parent.addChild(dest);
        }

        synchronized (source.children) {
            dest.isSetup                           = source.isSetup;
            dest.isSharingParentWildcardEvaluators = source.isSharingParentWildcardEvaluators;

            if (source.isSharingParentWildcardEvaluators) {
                if (dest.getParent() != null) {
                    dest.wildcardEvaluators = dest.getParent().getWildcardEvaluators();
                } else {
                    dest.wildcardEvaluators = null;
                }
            } else {
                if (source.wildcardEvaluators != null) {
                    dest.wildcardEvaluators = new HashSet<>(source.wildcardEvaluators);
                } else {
                    dest.wildcardEvaluators = null;
                }
            }

            if (source.evaluators != null) {
                if (source.evaluators == source.wildcardEvaluators) {
                    dest.evaluators = dest.wildcardEvaluators;
                } else {
                    dest.evaluators = new HashSet<>(source.evaluators);
                }
            } else {
                dest.evaluators = null;
            }
        }

        Map<Character, TrieNode<T>> children = source.getChildren();

        for (Map.Entry<Character, TrieNode<T>> entry : children.entrySet()) {
            copyTrieSubtree(entry.getValue(), dest);
        }

        if (TRACE_LOG.isTraceEnabled()) {
            StringBuilder sourceAsString = new StringBuilder();
            StringBuilder destAsString   = new StringBuilder();

            source.toString(sourceAsString);
            dest.toString(destAsString);

            TRACE_LOG.trace("<== copyTrieSubtree({}) : {}", sourceAsString, destAsString);
        }

        return dest;
    }

    private <E> TrieNode<T> buildTrie(RangerResourceDef resourceDef, List<E> evaluators, int builderThreadCount) {
        LOG.debug("==> buildTrie({}, evaluatorCount={}, isMultiThreaded={})", resourceDef.getName(), evaluators.size(), (builderThreadCount > 1));

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_INIT_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_INIT_LOG, "RangerResourceTrie.init(resourceDef=" + resourceDef.getName() + ")");
        }

        TrieNode<T>                           ret                 = new TrieNode<>(null);
        final boolean                         isMultiThreaded     = builderThreadCount > 1;
        final List<ResourceTrieBuilderThread> builderThreads;
        final Map<Character, Integer>         builderThreadMap;
        final String                          resourceName        = resourceDef.getName();
        int                                   lastUsedThreadIndex = 0;

        if (isMultiThreaded) {
            builderThreads = new ArrayList<>();

            for (int i = 0; i < builderThreadCount; i++) {
                ResourceTrieBuilderThread t = new ResourceTrieBuilderThread();

                t.setDaemon(true);
                builderThreads.add(t);
                t.start();
            }

            builderThreadMap = new HashMap<>();
        } else {
            builderThreads   = null;
            builderThreadMap = null;
        }

        for (E evaluator : evaluators) {
            final List<T> resourceEvaluators;

            if (evaluator instanceof RangerPolicyEvaluator) {
                resourceEvaluators = (List<T>) ((RangerPolicyEvaluator) evaluator).getResourceEvaluators();
            } else if (evaluator instanceof RangerResourceEvaluator) {
                resourceEvaluators = Collections.singletonList((T) evaluator);
            } else {
                LOG.error("buildTrie(): unexpected evaluator class {}", evaluator.getClass().getCanonicalName());

                resourceEvaluators = Collections.emptyList();
            }

            for (T resourceEvaluator : resourceEvaluators) {
                Map<String, RangerPolicyResource> policyResources = resourceEvaluator.getPolicyResource();
                RangerPolicyResource              policyResource  = policyResources != null ? policyResources.get(resourceName) : null;

                if (policyResource == null) {
                    if (resourceEvaluator.isAncestorOf(resourceDef)) {
                        addInheritedEvaluator(resourceEvaluator);
                    }

                    continue;
                }

                if (policyResource.getIsExcludes()) {
                    addInheritedEvaluator(resourceEvaluator);
                } else {
                    RangerResourceMatcher resourceMatcher = resourceEvaluator.getResourceMatcher(resourceName);

                    if (resourceMatcher != null && (resourceMatcher.isMatchAny())) {
                        ret.addWildcardEvaluator(resourceEvaluator);
                    } else {
                        if (CollectionUtils.isNotEmpty(policyResource.getValues())) {
                            for (String resource : policyResource.getValues()) {
                                if (!isMultiThreaded) {
                                    insert(ret, resource, policyResource.getIsRecursive(), resourceEvaluator);
                                } else {
                                    try {
                                        lastUsedThreadIndex = insert(ret, resource, policyResource.getIsRecursive(), resourceEvaluator, builderThreadMap, builderThreads, lastUsedThreadIndex);
                                    } catch (InterruptedException ex) {
                                        LOG.error("Failed to dispatch {} to {}", resource, builderThreads.get(lastUsedThreadIndex));
                                        LOG.error("Failing and retrying with one thread");

                                        ret = null;

                                        break;
                                    }
                                }
                            }

                            if (ret == null) {
                                break;
                            }
                        }
                    }
                }
            }

            if (ret == null) {
                break;
            }
        }

        if (ret != null) {
            if (isMultiThreaded) {
                for (ResourceTrieBuilderThread t : builderThreads) {
                    try {
                        // Send termination signal to each thread
                        t.add("", false, null);
                        // Wait for threads to finish work
                        t.join();
                        ret.getChildren().putAll(t.getSubtrees());
                    } catch (InterruptedException ex) {
                        LOG.error("BuilderThread {} was interrupted:", t, ex);
                        LOG.error("Failing and retrying with one thread");

                        ret = null;

                        break;
                    }
                }

                cleanUpThreads(builderThreads);
            }
        }

        RangerPerfTracer.logAlways(perf);

        LOG.debug("<== buildTrie({}, evaluatorCount={}, isMultiThreaded={}) :{}", resourceDef.getName(), evaluators.size(), isMultiThreaded, ret);

        return ret;
    }

    private void cleanUpThreads(List<ResourceTrieBuilderThread> builderThreads) {
        if (CollectionUtils.isNotEmpty(builderThreads)) {
            for (ResourceTrieBuilderThread t : builderThreads) {
                try {
                    if (t.isAlive()) {
                        t.interrupt();
                        t.join();
                    }
                } catch (InterruptedException ex) {
                    LOG.error("Could not terminate thread {}", t);
                }
            }
        }
    }

    private TrieData getTrieData() {
        TrieData ret = new TrieData();

        root.populateTrieData(ret);

        ret.maxDepth = getMaxDepth();

        return ret;
    }

    private int getMaxDepth() {
        return root.getMaxDepth();
    }

    private Character getLookupChar(char ch) {
        return optIgnoreCase ? Character.toLowerCase(ch) : ch;
    }

    private Character getLookupChar(String str, int index) {
        return getLookupChar(str.charAt(index));
    }

    private int insert(TrieNode<T> currentRoot, String resource, boolean isRecursive, T evaluator, Map<Character, Integer> builderThreadMap, List<ResourceTrieBuilderThread> builderThreads, int lastUsedThreadIndex) throws InterruptedException {
        int          ret    = lastUsedThreadIndex;
        final String prefix = getNonWildcardPrefix(resource);

        if (StringUtils.isNotEmpty(prefix)) {
            char    c     = getLookupChar(prefix.charAt(0));
            Integer index = builderThreadMap.get(c);

            if (index == null) {
                ret   = (lastUsedThreadIndex + 1) % builderThreads.size();
                index = ret;

                builderThreadMap.put(c, index);
            }

            builderThreads.get(index).add(resource, isRecursive, evaluator);
        } else {
            currentRoot.addWildcardEvaluator(evaluator);
        }

        return ret;
    }

    private void insert(TrieNode<T> currentRoot, String resource, boolean isRecursive, T evaluator) {
        TrieNode<T>   curr       = currentRoot;
        final String  prefix     = getNonWildcardPrefix(resource);
        final boolean isWildcard = prefix.length() != resource.length();

        if (StringUtils.isNotEmpty(prefix)) {
            curr = curr.getOrCreateChild(prefix);
        }

        if (isWildcard || isRecursive) {
            curr.addWildcardEvaluator(evaluator);
        } else {
            curr.addEvaluator(evaluator);
        }
    }

    private int getNonWildcardPrefixLength(String str) {
        int minIndex = str.length();

        for (int i = 0; i < wildcardChars.length(); i++) {
            int index = str.indexOf(wildcardChars.charAt(i));

            if (index != -1 && index < minIndex) {
                minIndex = index;
            }
        }

        return minIndex;
    }

    private String getNonWildcardPrefix(String str) {
        int prefixLen = getNonWildcardPrefixLength(str);

        return (prefixLen < str.length()) ? str.substring(0, prefixLen) : str;
    }

    private TrieNode<T> getNodeForResource(String resource) {
        LOG.debug("==> RangerResourceTrie.getNodeForResource({})", resource);

        RangerPerfTracer perf = null;

        if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_OP_LOG)) {
            perf = RangerPerfTracer.getPerfTracer(PERF_TRIE_OP_LOG, "RangerResourceTrie.getNodeForResource(resource=" + resource + ")");
        }

        TrieNode<T> curr = root;
        final int   len  = getNonWildcardPrefixLength(resource);
        int         i    = 0;

        while (i < len) {
            final TrieNode<T> child = curr.getChild(getLookupChar(resource, i));

            if (child == null) {
                break;
            }

            final String childStr = child.getStr();

            if (!resource.regionMatches(optIgnoreCase, i, childStr, 0, childStr.length())) {
                break;
            }

            curr = child;
            i += childStr.length();
        }

        curr = (i == len) ? curr : null;

        RangerPerfTracer.logAlways(perf);

        LOG.debug("<== RangerResourceTrie.getNodeForResource({})", resource);

        return curr;
    }

    public interface TraverseMatchHandler<T extends RangerResourceEvaluator> {
        // return: true  - stop traverse, processing is complete
        //         false - continue traverse, processing is not complete yet
        boolean process(Set<T> evaluators);
    }

    static class TrieData {
        int nodeCount;
        int leafNodeCount;
        int singleChildNodeCount;
        int maxDepth;
        int evaluatorListCount;
        int wildcardEvaluatorListCount;
        int evaluatorListRefCount;
        int wildcardEvaluatorListRefCount;
    }

    public static class EvalCollector<T extends RangerResourceEvaluator> implements TraverseMatchHandler<T> {
        private final Predicate predicate;
        private       Set<T>    result;
        private       boolean   isOwnedResult;

        public EvalCollector(Predicate predicate) {
            this.predicate = predicate;
            this.result    = null;
        }

        public Set<T> getResult() {
            return result;
        }

        @Override
        public boolean process(Set<T> evaluators) {
            if (evaluators != null && !evaluators.isEmpty()) {
                if (result == null) {
                    if (predicate == null) {
                        result = evaluators;
                    } else {
                        result        = new HashSet<>();
                        isOwnedResult = true;

                        for (T evaluator : evaluators) {
                            if (predicate.evaluate(evaluator)) {
                                result.add(evaluator);
                            }
                        }
                    }
                } else {
                    if (!isOwnedResult) {
                        result = new HashSet<>(result);

                        isOwnedResult = true;
                    }

                    if (predicate == null) {
                        result.addAll(evaluators);
                    } else {
                        for (T evaluator : evaluators) {
                            if (predicate.evaluate(evaluator)) {
                                result.add(evaluator);
                            }
                        }
                    }
                }
            }

            return false; // continue traverse
        }
    }

    public static class EvalSubsetCollector<T extends RangerResourceEvaluator> implements TraverseMatchHandler<T> {
        private final Predicate predicate;
        private final Set<T>    filter;
        private       Set<T>    result;

        public EvalSubsetCollector(Set<T> filter, Predicate predicate) {
            this.predicate = predicate;
            this.filter    = filter == null ? Collections.emptySet() : filter;
            this.result    = null;
        }

        public Set<T> getResult() {
            return result;
        }

        @Override
        public boolean process(Set<T> evaluators) {
            if (evaluators != null && !evaluators.isEmpty()) {
                if (result == null) {
                    result = new HashSet<>();
                }

                intersect(filter, evaluators, result);

                if (predicate != null) {
                    result.removeIf(evaluator -> !predicate.evaluate(evaluator));
                }
            }

            return result != null && (filter.size() == result.size()); // stop traverse once the result includes all entries in the filter
        }

        private static <T> void intersect(Set<T> a, Set<T> b, Set<T> result) {
            Set<T> smaller = a.size() < b.size() ? a : b;
            Set<T> larger  = smaller == a ? b : a;

            smaller.forEach(item -> {
                if (larger.contains(item)) {
                    result.add(item);
                }
            });
        }
    }

    public static class EvalCountCollector<T extends RangerResourceEvaluator> implements TraverseMatchHandler<T> {
        private final Predicate predicate;
        private       int       result;

        public EvalCountCollector(Predicate predicate) {
            this.predicate = predicate;
        }

        public int getResult() {
            return result;
        }

        @Override
        public boolean process(Set<T> evaluators) {
            if (evaluators != null) {
                if (predicate == null) {
                    result += evaluators.size();
                } else {
                    for (T evaluator : evaluators) {
                        if (predicate.evaluate(evaluator)) {
                            result++;
                        }
                    }
                }
            }

            return false; // continue traverse
        }
    }

    class ResourceTrieBuilderThread extends Thread {
        private final TrieNode<T>             thisRoot  = new TrieNode<>(null);
        private final BlockingQueue<WorkItem> workQueue = new LinkedBlockingQueue<>();

        ResourceTrieBuilderThread() {
        }

        @Override
        public void run() {
            LOG.debug("Running {}", this);

            while (true) {
                final WorkItem workItem;

                try {
                    workItem = workQueue.take();
                } catch (InterruptedException exception) {
                    LOG.error("Thread={} is interrupted", this, exception);

                    break;
                }

                if (workItem.evaluator != null) {
                    insert(thisRoot, workItem.resourceName, workItem.isRecursive, workItem.evaluator);
                } else {
                    LOG.debug("Received termination signal. {}", workItem);

                    break;
                }
            }

            LOG.debug("Exiting {}", this);
        }

        void add(String resourceName, boolean isRecursive, T evaluator) throws InterruptedException {
            workQueue.put(new WorkItem(resourceName, isRecursive, evaluator));
        }

        Map<Character, TrieNode<T>> getSubtrees() {
            return thisRoot.getChildren();
        }

        class WorkItem {
            final String  resourceName;
            final boolean isRecursive;
            final T       evaluator;

            WorkItem(String resourceName, boolean isRecursive, T evaluator) {
                this.resourceName = resourceName;
                this.isRecursive  = isRecursive;
                this.evaluator    = evaluator;
            }

            @Override
            public String toString() {
                return "resourceName=" + resourceName +
                        "isRecursive=" + isRecursive +
                        "evaluator=" + (evaluator != null ? evaluator.getId() : null);
            }
        }
    }

    class TrieNode<U extends T> {
        private final    Map<Character, TrieNode<U>> children = new HashMap<>();
        private          String                      str;
        private          TrieNode<U>                 parent;
        private volatile Set<U>                      evaluators;
        private volatile Set<U>                      wildcardEvaluators;
        private          boolean                     isSharingParentWildcardEvaluators;
        private volatile boolean                     isSetup;

        TrieNode(String str) {
            this.str = str;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            toString(sb);
            return sb.toString();
        }

        String getStr() {
            return str;
        }

        void setStr(String str) {
            this.str = str;
        }

        TrieNode<U> getParent() {
            return parent;
        }

        void setParent(TrieNode<U> parent) {
            this.parent = parent;
        }

        Map<Character, TrieNode<U>> getChildren() {
            return children;
        }

        Set<U> getEvaluators() {
            return evaluators;
        }

        Set<U> getWildcardEvaluators() {
            return wildcardEvaluators;
        }

        TrieNode<U> getChild(Character ch) {
            return children.get(ch);
        }

        void populateTrieData(RangerResourceTrie.TrieData trieData) {
            trieData.nodeCount++;

            if (wildcardEvaluators != null) {
                if (isSharingParentWildcardEvaluators) {
                    trieData.wildcardEvaluatorListRefCount++;
                } else {
                    trieData.wildcardEvaluatorListCount++;
                }
            }

            if (evaluators != null) {
                if (evaluators == wildcardEvaluators) {
                    trieData.evaluatorListRefCount++;
                } else {
                    trieData.evaluatorListCount++;
                }
            }

            if (!children.isEmpty()) {
                if (children.size() == 1) {
                    trieData.singleChildNodeCount++;
                }

                for (Map.Entry<Character, TrieNode<U>> entry : children.entrySet()) {
                    TrieNode<U> child = entry.getValue();

                    child.populateTrieData(trieData);
                }
            } else {
                trieData.leafNodeCount++;
            }
        }

        int getMaxDepth() {
            int ret = 0;

            for (Map.Entry<Character, TrieNode<U>> entry : children.entrySet()) {
                TrieNode<U> child = entry.getValue();

                int maxChildDepth = child.getMaxDepth();

                if (maxChildDepth > ret) {
                    ret = maxChildDepth;
                }
            }

            return ret + 1;
        }

        TrieNode<U> getOrCreateChild(String str) {
            int         len   = str.length();
            TrieNode<U> child = children.get(getLookupChar(str, 0));

            if (child == null) {
                child = new TrieNode<>(str);

                addChild(child);
            } else {
                final String  childStr     = child.getStr();
                final int     childStrLen  = childStr.length();
                final boolean isExactMatch = optIgnoreCase ? StringUtils.equalsIgnoreCase(childStr, str) : StringUtils.equals(childStr, str);

                if (!isExactMatch) {
                    final int numOfCharactersToMatch = Math.min(childStrLen, len);
                    int       index                  = 1;

                    for (; index < numOfCharactersToMatch; index++) {
                        if (getLookupChar(childStr, index) != getLookupChar(str, index)) {
                            break;
                        }
                    }

                    if (index == numOfCharactersToMatch) {
                        // Matched all
                        if (childStrLen > len) {
                            // Existing node has longer string, need to break up this node
                            TrieNode<U> newChild = new TrieNode<>(str);

                            this.addChild(newChild);
                            child.setStr(childStr.substring(index));
                            newChild.addChild(child);

                            child = newChild;
                        } else {
                            // This is a longer string, build a child with leftover string
                            child = child.getOrCreateChild(str.substring(index));
                        }
                    } else {
                        // Partial match for both; both have leftovers
                        String      matchedPart = str.substring(0, index);
                        TrieNode<U> newChild    = new TrieNode<>(matchedPart);

                        this.addChild(newChild);
                        child.setStr(childStr.substring(index));
                        newChild.addChild(child);

                        child = newChild.getOrCreateChild(str.substring(index));
                    }
                }
            }

            return child;
        }

        void addEvaluator(U evaluator) {
            if (evaluators == null) {
                evaluators = new HashSet<>();
            }

            evaluators.add(evaluator);
        }

        void addWildcardEvaluator(U evaluator) {
            if (wildcardEvaluators == null) {
                wildcardEvaluators = new HashSet<>();
            }

            wildcardEvaluators.add(evaluator);
        }

        void removeEvaluator(U evaluator) {
            if (CollectionUtils.isNotEmpty(evaluators)) {
                evaluators.remove(evaluator);

                if (CollectionUtils.isEmpty(evaluators)) {
                    evaluators = null;
                }
            }
        }

        void removeWildcardEvaluator(U evaluator) {
            if (CollectionUtils.isNotEmpty(wildcardEvaluators)) {
                wildcardEvaluators.remove(evaluator);

                if (CollectionUtils.isEmpty(wildcardEvaluators)) {
                    wildcardEvaluators = null;
                }
            }
        }

        void undoSetup() {
            for (TrieNode<U> child : children.values()) {
                child.undoSetup();
            }

            if (isSetup) {
                if (evaluators != null) {
                    if (evaluators == wildcardEvaluators) {
                        evaluators = null;
                    } else {
                        if (wildcardEvaluators != null) {
                            evaluators.removeAll(wildcardEvaluators);

                            if (CollectionUtils.isEmpty(evaluators)) {
                                evaluators = null;
                            }
                        }
                    }
                }

                if (wildcardEvaluators != null) {
                    if (isSharingParentWildcardEvaluators) {
                        wildcardEvaluators = null;
                    } else {
                        Set<U> parentWildcardEvaluators = getParent() == null ? null : getParent().getWildcardEvaluators();

                        if (parentWildcardEvaluators != null) {
                            wildcardEvaluators.removeAll(parentWildcardEvaluators);

                            if (CollectionUtils.isEmpty(wildcardEvaluators)) {
                                wildcardEvaluators = null;
                            }
                        }
                    }
                }

                isSharingParentWildcardEvaluators = false;
                isSetup                           = false;
            }
        }

        void removeSelfFromTrie() {
            LOG.debug("==> removeSelfFromTrie({})", this);

            if (evaluators == null && wildcardEvaluators == null && children.isEmpty()) {
                TrieNode<U> parent = getParent();

                if (parent != null) {
                    parent.children.remove(str.charAt(0));
                }
            } else {
                LOG.debug("removeSelfFromTrie({}): node is not removed from Trie : [evaluators:{}, wildcard-evaluators:{}, number-of-children-nodes:{}]", this, evaluators, wildcardEvaluators, children.size());
            }

            LOG.debug("<== removeSelfFromTrie({})", this);
        }

        void wrapUpUpdate() {
            if (isOptimizedForRetrieval) {
                RangerPerfTracer postSetupPerf = null;

                if (RangerPerfTracer.isPerfTraceEnabled(PERF_TRIE_INIT_LOG)) {
                    postSetupPerf = RangerPerfTracer.getPerfTracer(PERF_TRIE_INIT_LOG, "RangerResourceTrie.init(name=" + resourceDef.getName() + "-postSetup)");
                }

                postSetup(null);

                RangerPerfTracer.logAlways(postSetupPerf);
            }
        }

        void postSetup(Set<U> parentWildcardEvaluators) {
            setup(parentWildcardEvaluators);

            for (Map.Entry<Character, TrieNode<U>> entry : children.entrySet()) {
                TrieNode<U> child = entry.getValue();

                child.postSetup(wildcardEvaluators);
            }
        }

        void setupIfNeeded(TrieNode<U> parent) {
            boolean setupNeeded = !isSetup;

            if (setupNeeded) {
                synchronized (this.children) {
                    setupNeeded = !isSetup;

                    if (setupNeeded) {
                        setup(parent == null ? null : parent.getWildcardEvaluators());

                        if (TRACE_LOG.isTraceEnabled()) {
                            StringBuilder sb = new StringBuilder();

                            this.toString(sb);

                            TRACE_LOG.trace("Set up is completed for this TriNode as a part of access evaluation : [{}]", sb);
                        }
                    }
                }
            }
        }

        void setup(Set<U> parentWildcardEvaluators) {
            if (!isSetup) {
                // finalize wildcard-evaluators list by including parent's wildcard evaluators
                if (parentWildcardEvaluators != null) {
                    if (CollectionUtils.isEmpty(this.wildcardEvaluators)) {
                        this.wildcardEvaluators = parentWildcardEvaluators;
                    } else {
                        for (U evaluator : parentWildcardEvaluators) {
                            addWildcardEvaluator(evaluator);
                        }
                    }
                }

                this.isSharingParentWildcardEvaluators = wildcardEvaluators == parentWildcardEvaluators;

                // finalize evaluators list by including wildcard evaluators
                if (wildcardEvaluators != null) {
                    if (CollectionUtils.isEmpty(this.evaluators)) {
                        this.evaluators = wildcardEvaluators;
                    } else {
                        for (U evaluator : wildcardEvaluators) {
                            addEvaluator(evaluator);
                        }
                    }
                }
                isSetup = true;
            }
        }

        void collectChildEvaluators(Character sep, int startIdx, TraverseMatchHandler<U> handler) {
            if (!isOptimizedForSpace) {
                setupIfNeeded(getParent());
            }

            final int sepPos = startIdx < str.length() ? str.indexOf(sep, startIdx) : -1;

            if (sepPos == -1) { // ex: startIdx=5, path(str)=/tmp/test, path(a child) could be: /tmp/test.txt, /tmp/test/, /tmp/test/a, /tmp/test/a/b
                if (isOptimizedForSpace) {
                    handler.process(this.wildcardEvaluators);
                }

                handler.process(this.evaluators);

                children.values().forEach(c -> c.collectChildEvaluators(sep, 0, handler));
            } else if (sepPos == (str.length() - 1)) { // ex: str=/tmp/test/, startIdx=5
                if (isOptimizedForSpace) {
                    handler.process(this.wildcardEvaluators);
                }

                handler.process(this.evaluators);
            }
        }

        void collectChildEvaluators(String resource, int startIndex, TraverseMatchHandler<U> handler) {
            if (startIndex == resource.length()) {
                collectChildEvaluators(handler);
            } else if (startIndex < resource.length()) {
                Character   startChar = getLookupChar(resource, startIndex);
                TrieNode<U> childNode = children.get(startChar);

                if (childNode != null) {
                    if (!isOptimizedForSpace) {
                        childNode.setupIfNeeded(childNode.getParent());
                    }

                    String childStr   = childNode.getStr();
                    int    lenToMatch = Math.min(resource.length() - startIndex, childStr.length());

                    if (resource.regionMatches(optIgnoreCase, startIndex, childStr, 0, lenToMatch)) {
                        handler.process(childNode.wildcardEvaluators);
                        handler.process(childNode.evaluators);

                        if (resource.length() == (startIndex + lenToMatch)) {
                            childNode.collectChildEvaluators(handler);
                        } else {
                            childNode.children.values().forEach(c -> c.collectChildEvaluators(resource, startIndex + childStr.length(), handler));
                        }
                    }
                }
            }
        }

        void toString(StringBuilder sb) {
            String nodeValue = this.str;

            sb.append("nodeValue=").append(nodeValue == null ? "ROOT" : nodeValue);
            sb.append("; isSetup=").append(isSetup);
            sb.append("; isSharingParentWildcardEvaluators=").append(isSharingParentWildcardEvaluators);
            sb.append("; childCount=").append(children.size());
            sb.append("; evaluators=[");
            if (evaluators != null) {
                for (U evaluator : evaluators) {
                    sb.append(evaluator.getId()).append("|,|");
                }
            }
            sb.append("]");

            sb.append("; wildcardEvaluators=[ ");
            if (wildcardEvaluators != null) {
                for (U evaluator : wildcardEvaluators) {
                    sb.append(evaluator.getId()).append("|,|");
                }
            }
            sb.append("]");
        }

        void toString(String prefix, StringBuilder sb) {
            String nodeValue = prefix + (str != null ? str : "");

            if (!nodeValue.equals(prefix)) {
                prefix = prefix + "|";
            }

            sb.append(prefix);
            toString(sb);
            sb.append("]\n");

            for (Map.Entry<Character, TrieNode<U>> entry : children.entrySet()) {
                TrieNode<U> child = entry.getValue();

                child.toString(nodeValue, sb);
            }
        }

        private void addChild(TrieNode<U> child) {
            children.put(getLookupChar(child.getStr(), 0), child);
            child.setParent(this);
        }

        private void collectChildEvaluators(TraverseMatchHandler<U> childEvaluators) {
            Stack<TrieNode<U>> nodes = new Stack<>();

            nodes.addAll(children.values());

            while (!nodes.isEmpty()) {
                TrieNode<U> childNode = nodes.pop();

                if (!isOptimizedForSpace) {
                    childNode.setupIfNeeded(childNode.getParent());
                }

                childEvaluators.process(childNode.wildcardEvaluators);
                childEvaluators.process(childNode.evaluators);

                nodes.addAll(childNode.children.values());
            }
        }

        private void removeEvaluatorFromSubtree(U evaluator) {
            LOG.debug("==> removeEvaluatorFromSubtree({})", evaluator.getId());

            if (CollectionUtils.isNotEmpty(wildcardEvaluators) && wildcardEvaluators.contains(evaluator)) {
                removeWildcardEvaluator(evaluator);
            } else {
                removeEvaluator(evaluator);
            }

            removeSelfFromTrie();

            LOG.debug("<== removeEvaluatorFromSubtree({})", evaluator.getId());
        }
    }
}
