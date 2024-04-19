/*
 *  Copyright (c)  WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.entitlement.dao;

import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;

import java.util.Properties;

/**
 * This manages the policy versions
 */
public interface PolicyVersionManagerModule {

    /**
     * init policy version handler
     *
     * @param properties properties
     */
    void init(Properties properties);

    /**
     * @param policyId policyId
     * @param version  policy version
     * @return policyDTO
     * @throws EntitlementException throws, if fails
     */
    PolicyDTO getPolicy(String policyId, String version) throws EntitlementException;

    /**
     * @param policyDTO policyDTO
     * @return version
     * @throws EntitlementException throws, if fails
     */
    String createVersion(PolicyDTO policyDTO) throws EntitlementException;


    /**
     * @param policyId policyId
     * @return String[] of policy versions
     * @throws EntitlementException throws, if fails
     */
    String[] getVersions(String policyId) throws EntitlementException;
}
