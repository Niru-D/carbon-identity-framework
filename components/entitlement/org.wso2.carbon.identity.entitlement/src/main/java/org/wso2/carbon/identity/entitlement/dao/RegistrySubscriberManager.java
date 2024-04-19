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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.dto.PublisherDataHolder;
import org.wso2.carbon.identity.entitlement.dto.PublisherPropertyDTO;
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * This is for subscriber management
 */
public class RegistrySubscriberManager implements SubscriberManagerModule {

    public static final String SUBSCRIBER_ID = "subscriberId";
    private static final Log log = LogFactory.getLog(RegistrySubscriberManager.class);

    private final Registry registry;


    /**
     * Creates a subscriber manager
     */
    public RegistrySubscriberManager() {
        this.registry = EntitlementServiceComponent.
                getGovernanceRegistry(CarbonContext.getThreadLocalCarbonContext().getTenantId());
    }


    /**
     * Adds a subscriber
     */
    @Override
    public void persistSubscriber(PublisherDataHolder holder, boolean update) throws EntitlementException {

        Collection policyCollection;
        String subscriberPath;
        String subscriberId = null;

        if (holder == null || holder.getPropertyDTOs() == null) {
            log.error("Publisher data can not be null");
            throw new EntitlementException("Publisher data can not be null");
        }

        for (PublisherPropertyDTO dto : holder.getPropertyDTOs()) {
            if (SUBSCRIBER_ID.equals(dto.getId())) {
                subscriberId = dto.getValue();
            }
        }

        if (subscriberId == null) {
            log.error("Subscriber Id can not be null");
            throw new EntitlementException("Subscriber Id can not be null");
        }

        try {
            if (registry.resourceExists(PDPConstants.ENTITLEMENT_POLICY_PUBLISHER)) {
                policyCollection = registry.newCollection();
                registry.put(PDPConstants.ENTITLEMENT_POLICY_PUBLISHER, policyCollection);
            }

            subscriberPath = PDPConstants.ENTITLEMENT_POLICY_PUBLISHER +
                    RegistryConstants.PATH_SEPARATOR + subscriberId;

            Resource resource;

            PublisherDataHolder oldHolder = null;
            if (registry.resourceExists(subscriberPath)) {
                if (update) {
                    resource = registry.get(subscriberPath);
                    oldHolder = new PublisherDataHolder(resource, false);
                } else {
                    throw new EntitlementException("Subscriber ID already exists");
                }
            } else {
                resource = registry.newResource();
            }

            populateProperties(holder, oldHolder, resource);
            registry.put(subscriberPath, resource);

        } catch (RegistryException e) {
            log.error("Error while persisting subscriber details", e);
            throw new EntitlementException("Error while persisting subscriber details", e);
        }
    }


    /**
     * Deletes a subscriber
     */
    @Override
    public void deleteSubscriber(String subscriberId) throws EntitlementException {

        String subscriberPath;

        if (subscriberId == null) {
            log.error("Subscriber Id can not be null");
            throw new EntitlementException("Subscriber Id can not be null");
        }

        if (EntitlementConstants.PDP_SUBSCRIBER_ID.equals(subscriberId.trim())) {
            log.error("Can not delete PDP publisher");
            throw new EntitlementException("Can not delete PDP publisher");
        }

        try {
            subscriberPath = PDPConstants.ENTITLEMENT_POLICY_PUBLISHER +
                    RegistryConstants.PATH_SEPARATOR + subscriberId;

            if (registry.resourceExists(subscriberPath)) {
                registry.delete(subscriberPath);
            }
        } catch (RegistryException e) {
            log.error("Error while deleting subscriber details", e);
            throw new EntitlementException("Error while deleting subscriber details", e);
        }
    }


    /**
     * Retrieves a subscriber
     */
    @Override
    public PublisherDataHolder retrieveSubscriber(String id, boolean returnSecrets) throws EntitlementException {

        try {
            if (registry.resourceExists(PDPConstants.ENTITLEMENT_POLICY_PUBLISHER +
                    RegistryConstants.PATH_SEPARATOR + id)) {
                Resource resource = registry.get(PDPConstants.ENTITLEMENT_POLICY_PUBLISHER +
                        RegistryConstants.PATH_SEPARATOR + id);

                return new PublisherDataHolder(resource, returnSecrets);
            }
        } catch (RegistryException e) {
            log.error("Error while retrieving subscriber detail of id : " + id, e);
            throw new EntitlementException("Error while retrieving subscriber detail of id : " + id, e);
        }

        throw new EntitlementException("No Subscriber is defined for given Id");
    }


    /**
     * Retrieves subscriber ids
     */
    @Override
    public String[] retrieveSubscriberIds(String searchString) throws EntitlementException {

        try {
            if (registry.resourceExists(PDPConstants.ENTITLEMENT_POLICY_PUBLISHER +
                    RegistryConstants.PATH_SEPARATOR)) {
                Resource resource = registry.get(PDPConstants.ENTITLEMENT_POLICY_PUBLISHER +
                        RegistryConstants.PATH_SEPARATOR);
                Collection collection = (Collection) resource;
                List<String> list = new ArrayList<>();
                if (collection.getChildCount() > 0) {
                    searchString = searchString.replace("*", ".*");
                    Pattern pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE);
                    for (String path : collection.getChildren()) {
                        String id = path.substring(path.lastIndexOf(RegistryConstants.PATH_SEPARATOR) + 1);
                        Matcher matcher = pattern.matcher(id);
                        if (!matcher.matches()) {
                            continue;
                        }
                        Resource childResource = registry.get(path);
                        if (childResource != null && childResource.getProperty(SUBSCRIBER_ID) != null) {
                            list.add(childResource.getProperty(SUBSCRIBER_ID));
                        }
                    }
                }
                return list.toArray(new String[0]);
            }
        } catch (RegistryException e) {
            log.error("Error while retrieving subscriber of ids", e);
            throw new EntitlementException("Error while retrieving subscriber ids", e);

        }

        return null;
    }


    private void populateProperties(PublisherDataHolder holder,
                                    PublisherDataHolder oldHolder, Resource resource) {

        PublisherPropertyDTO[] propertyDTOs = holder.getPropertyDTOs();
        for (PublisherPropertyDTO dto : propertyDTOs) {
            if (dto.getId() != null && dto.getValue() != null && !dto.getValue().trim().isEmpty()) {
                ArrayList<String> list = new ArrayList<>();
                if (dto.isSecret()) {
                    PublisherPropertyDTO propertyDTO = null;
                    if (oldHolder != null) {
                        propertyDTO = oldHolder.getPropertyDTO(dto.getId());
                    }
                    if (propertyDTO == null || !propertyDTO.getValue().equalsIgnoreCase(dto.getValue())) {
                        try {
                            String encryptedValue = CryptoUtil.getDefaultCryptoUtil().
                                    encryptAndBase64Encode(dto.getValue().getBytes());
                            dto.setValue(encryptedValue);
                        } catch (CryptoException e) {
                            log.error("Error while encrypting secret value of subscriber. " +
                                    "Secret would not be persist.", e);
                            continue;
                        }
                    }
                }
                list.add(dto.getValue());
                list.add(dto.getDisplayName());
                list.add(Integer.toString(dto.getDisplayOrder()));
                list.add(Boolean.toString(dto.isRequired()));
                list.add(Boolean.toString(dto.isSecret()));
                resource.setProperty(dto.getId(), list);
            }
        }
        resource.setProperty(PublisherDataHolder.MODULE_NAME, holder.getModuleName());
    }

}
