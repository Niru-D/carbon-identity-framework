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
import org.wso2.carbon.identity.entitlement.dto.PublisherDataHolder;


/**
 * This interface supports subscriber management
 */
public interface SubscriberManagerModule {

    /**
     * Creates a subscriber manager
     */
    public void SubscriberManager();


    /**
     * Adds a subscriber
     */
    public void persistSubscriber(PublisherDataHolder holder, boolean update) throws EntitlementException;

    /**
     * Deletes a subscriber
     */
    public void deleteSubscriber(String subscriberId) throws EntitlementException;


    /**
     * Retrieves a subscriber
     */
    public PublisherDataHolder retrieveSubscriber(String id, boolean returnSecrets) throws EntitlementException;


    /**
     * Retrieves subscriber ids
     */
    public String[] retrieveSubscriberIds(String searchString) throws EntitlementException;


}
