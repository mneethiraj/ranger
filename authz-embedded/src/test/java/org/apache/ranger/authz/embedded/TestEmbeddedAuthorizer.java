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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.ranger.authz.model.RangerAuthzRequest;
import org.apache.ranger.authz.model.RangerAuthzResult;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestEmbeddedAuthorizer {
    private static final TypeReference<List<TestData>> TYPE_LIST_TEST_DATA = new TypeReference<List<TestData>>() {};

    @Test
    public void testS3() throws Exception {
        runTest("test_s3");
    }

    private void runTest(String testName) throws Exception {
        String propertiesPath = "/" + testName + "/ranger-embedded-authz.properties";
        String testsPath      = "/" + testName + "/tests.json";

        RangerEmbeddedAuthorizer authorizer = null;

        try {
            authorizer = new RangerEmbeddedAuthorizer(loadProperties(propertiesPath));

            authorizer.init();

            System.out.println("Authorizer initialized");

            for (TestData test : loadTestData(testsPath)) {
                if (test.request == null || test.result == null) {
                    continue;
                }

                RangerAuthzRequest request = test.request;
                RangerAuthzResult  expected = test.result;
                RangerAuthzResult  result   = authorizer.authorize(request);

                assertEquals(expected, result);
            }
        } finally {
            if (authorizer != null) {
                authorizer.close();
            }
        }
    }

    private Properties loadProperties(String resourcePath) throws Exception {
        Properties properties = new Properties();

        try (InputStream in = getClass().getResourceAsStream(resourcePath)) {
            properties.load(in);
        }

        return properties;
    }

    private List<TestData> loadTestData(String resourcePath) throws Exception {
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        try (InputStream in = getClass().getResourceAsStream(resourcePath)) {
            return mapper.readValue(in, TYPE_LIST_TEST_DATA);
        }
    }

    private static class TestData {
        public RangerAuthzRequest request;
        public RangerAuthzResult  result;
    }
}
