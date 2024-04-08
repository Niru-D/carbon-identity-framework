/*
*  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

/**
 * This interface supports to retrieve data from the PAP
 */
public interface PAPPolicyStoreModule {

    /**
     * Initializes PAP Policy Store module
     */
    public void PAPPolicyStore();


    /**
     * Returns all policy ids
     */
    public String[] getAllPolicyIds() throws EntitlementException;


    /**
     * Returns required policy
     */
    public PolicyDTO getPolicy(String policyId) throws EntitlementException;


    /**
     * Returns the requested policy version
     */
    public PolicyDTO getPolicyByVersion(String policyId, String version) throws EntitlementException;


    /**
     * Returns all policies
     */
    public PolicyDTO[] getAllPolicies() throws EntitlementException;


    /**
     * Adds the given policy to the policy store
     */
    public void addOrUpdatePolicy(PolicyDTO policy) throws EntitlementException;


    /**
     * Removes the given policy from the policy store
     */
    public void removePolicy(String policyId) throws EntitlementException;


    /**
     * Removes the given policy version from the policy store
     */
    public void removePolicyByVersion(String policyId, int version) throws EntitlementException;


}
