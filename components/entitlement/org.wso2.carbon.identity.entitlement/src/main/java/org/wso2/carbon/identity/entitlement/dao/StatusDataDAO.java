/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

package org.wso2.carbon.identity.entitlement.dao;

import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.dto.StatusHolder;

import java.util.List;


/**
 * This interface supports the management of status data (audit logs).
 */
public interface StatusDataDAO {


    /**
     * Handles policy status data
     */
    void handlePolicyStatusData(String policyId, List<StatusHolder> statusHolders) throws EntitlementException;


    /**
     * Handles subscriber status data
     */
    void handleSubscriberStatusData(String subscriberId, List<StatusHolder> statusHolders) throws EntitlementException;


    /**
     * Gets the requested policy status data
     */
    StatusHolder[] getPolicyStatusData(String policyId, String type, String filter) throws EntitlementException;


    /**
     * Gets the requested subscriber status data
     */
    StatusHolder[] getSubscriberStatusData(String subscriberId, String type, String filter) throws EntitlementException;


    /**
     * Removes status data
     */
    void removeStatusData(String path) throws EntitlementException;

}
