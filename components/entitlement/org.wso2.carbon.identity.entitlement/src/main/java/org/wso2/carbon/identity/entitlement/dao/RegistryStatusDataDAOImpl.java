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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.EntitlementUtil;
import org.wso2.carbon.identity.entitlement.StatusHolderComparator;
import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.dto.StatusHolder;
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Registry implementation of the StatusDataDAO
 */
public class RegistryStatusDataDAOImpl implements StatusDataDAO {


    // The logger that is used for all messages
    private static final Log log = LogFactory.getLog(RegistryStatusDataDAOImpl.class);
    private static final String ENTITLEMENT_POLICY_STATUS = "/repository/identity/entitlement/status/policy/";
    private static final String ENTITLEMENT_PUBLISHER_STATUS = "/repository/identity/entitlement/status/publisher/";


    @Override
    public void init(Properties properties) {

    }


    /**
     * Handles policy/subscriber status data
     *
     * @param about whether the operation is related to a policy or a subscriber
     * @param key policy ID/ subscriber ID
     * @param statusHolder list of status holders
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void handle(String about, String key, List<StatusHolder> statusHolder)
            throws EntitlementException {


        if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {
            String path = ENTITLEMENT_POLICY_STATUS + key;
            // Deletes policy data
            for (StatusHolder holder : statusHolder) {
                if (EntitlementConstants.StatusTypes.DELETE_POLICY.equals(holder.getType())) {
                    removeStatusData(path);
                    return;
                }
            }
            addStatusData(path, statusHolder, false);
        } else {
            String path = ENTITLEMENT_PUBLISHER_STATUS + key;
            // Deletes subscriber data
            for (StatusHolder holder : statusHolder) {
                if (EntitlementConstants.StatusTypes.DELETE_POLICY.equals(holder.getType())) {
                    removeStatusData(path);
                    return;
                }
            }
            addStatusData(path, statusHolder, false);
        }

    }


    @Override
    public void handle(String about, StatusHolder statusHolder) throws EntitlementException {
        List<StatusHolder> list = new ArrayList<StatusHolder>();
        list.add(statusHolder);
        handle(about, statusHolder.getKey(), list);
    }


    /**
     * Gets the requested policy/subscriber status data
     *
     * @param about whether the operation is related to a policy or a subscriber
     * @param key policy ID/ subscriber ID
     * @param type admin action type
     * @param searchString search string
     * @return array of status holders
     * @throws EntitlementException throws, if fails
     */
    @Override
    public StatusHolder[] getStatusData(String about, String key, String type, String searchString)
            throws EntitlementException {

        if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {
            String path = ENTITLEMENT_POLICY_STATUS + key;
            List<StatusHolder> holders = getStatusData(path, EntitlementConstants.Status.ABOUT_POLICY);
            List<StatusHolder> filteredHolders = new ArrayList<StatusHolder>();
            if (holders != null) {
                searchString = searchString.replace("*", ".*");
                Pattern pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE);
                for (StatusHolder holder : holders) {
                    String id = holder.getUser();
                    Matcher matcher = pattern.matcher(id);
                    if (!matcher.matches()) {
                        continue;
                    }
                    if (type != null && type.equals(holder.getType())) {
                        filteredHolders.add(holder);
                    } else if (type == null) {
                        filteredHolders.add(holder);
                    }
                }
            }
            return filteredHolders.toArray(new StatusHolder[filteredHolders.size()]);
        } else {
            List<StatusHolder> filteredHolders = new ArrayList<StatusHolder>();
            String path = ENTITLEMENT_PUBLISHER_STATUS + key;
            List<StatusHolder> holders = getStatusData(path, EntitlementConstants.Status.ABOUT_SUBSCRIBER);
            if (holders != null) {
                searchString = searchString.replace("*", ".*");
                Pattern pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE);
                for (StatusHolder holder : holders) {
                    String id = holder.getTarget();
                    Matcher matcher = pattern.matcher(id);
                    if (!matcher.matches()) {
                        continue;
                    }
                    filteredHolders.add(holder);
                }
            }
            return filteredHolders.toArray(new StatusHolder[filteredHolders.size()]);
        }
    }


    /**
     * Adds status data to the registry
     *
     * @param path registry path
     * @param statusHolders list of status holders
     * @param isNew whether this is a status data minimization or not
     * @throws EntitlementException throws, if fails
     */
    private synchronized void addStatusData(String path, List<StatusHolder> statusHolders, boolean isNew)
            throws EntitlementException {

        Resource resource;
        Registry registry;
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        try {
            registry = EntitlementServiceComponent.getRegistryService().getGovernanceSystemRegistry(tenantId);
            boolean useLastStatusOnly =
                    Boolean.parseBoolean(IdentityUtil.getProperty(EntitlementConstants.PROP_USE_LAST_STATUS_ONLY));
            if (registry.resourceExists(path) && !isNew && !useLastStatusOnly) {
                resource = registry.get(path);
                String[] versions = registry.getVersions(path);
                // Removes all versions, as there is no way to disable versioning for a specific resource
                if (versions != null) {
                    for (String version : versions) {
                        long versionInt = 0;
                        String[] versionStrings = version.split(RegistryConstants.VERSION_SEPARATOR);
                        if (versionStrings.length == 2) {
                            try {
                                versionInt = Long.parseLong(versionStrings[1]);
                            } catch (Exception e) {
                                // ignore
                            }
                        }
                        if (versionInt != 0) {
                            registry.removeVersionHistory(version, versionInt);
                        }
                    }
                }
            } else {
                resource = registry.newResource();
            }

            if (resource != null && statusHolders != null && !statusHolders.isEmpty()) {
                resource.setVersionableChange(false);
                populateStatusProperties(statusHolders.toArray(new StatusHolder[0]), resource);
                registry.put(path, resource);
            }
        } catch (RegistryException e) {
            log.error(e);
            throw new EntitlementException("Error while persisting status data", e);
        }
    }


    /**
     * Gets status data
     *
     * @param path registry path
     * @param statusType whether the status is related to a policy or a subscriber
     * @return list of status holders
     * @throws EntitlementException throws, if fails
     */
    private synchronized List<StatusHolder> getStatusData(String path, String statusType) throws EntitlementException {

        Resource resource = null;
        Registry registry;
        int maxRecords = EntitlementUtil.getMaxNoOfStatusRecords();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            registry = EntitlementServiceComponent.getRegistryService().getGovernanceSystemRegistry(tenantId);
            if (registry.resourceExists(path)) {
                resource = registry.get(path);
            }
        } catch (RegistryException e) {
            log.error(e);
            throw new EntitlementException("Error while persisting policy status", e);
        }

        List<StatusHolder> statusHolders = new ArrayList<>();
        if (resource != null && resource.getProperties() != null) {
            Properties properties = resource.getProperties();
            for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof ArrayList) {
                    List list = (ArrayList) entry.getValue();
                    if (!list.isEmpty() && list.get(0) != null) {
                        StatusHolder statusHolder = new StatusHolder(statusType);
                        if (list.get(0) != null) {
                            statusHolder.setType((String) list.get(0));
                        }
                        if (list.size() > 1 && list.get(1) != null) {
                            statusHolder.setTimeInstance((String) list.get(1));
                        } else {
                            continue;
                        }
                        if (list.size() > 2 && list.get(2) != null) {
                            String user = (String) list.get(2);
                            statusHolder.setUser(user);
                        } else {
                            continue;
                        }
                        if (list.size() > 3 && list.get(3) != null) {
                            statusHolder.setKey((String) list.get(3));
                        }
                        if (list.size() > 4 && list.get(4) != null) {
                            statusHolder.setSuccess(Boolean.parseBoolean((String) list.get(4)));
                        }
                        if (list.size() > 5 && list.get(5) != null) {
                            statusHolder.setMessage((String) list.get(5));
                        }
                        if (list.size() > 6 && list.get(6) != null) {
                            statusHolder.setTarget((String) list.get(6));
                        }
                        if (list.size() > 7 && list.get(7) != null) {
                            statusHolder.setTargetAction((String) list.get(7));
                        }
                        if (list.size() > 8 && list.get(8) != null) {
                            statusHolder.setVersion((String) list.get(8));
                        }
                        statusHolders.add(statusHolder);
                    }
                }
            }
        }
        if (!statusHolders.isEmpty()) {
            StatusHolder[] array = statusHolders.toArray(new StatusHolder[0]);
            Arrays.sort(array, new StatusHolderComparator());
            if (statusHolders.size() > maxRecords) {
                statusHolders = new ArrayList<>(Arrays.asList(array).subList(0, maxRecords));
                addStatusData(path, statusHolders, true);
            } else {
                statusHolders = new ArrayList<>(Arrays.asList(array));
            }
        }
        return statusHolders;
    }


    /**
     * Populate status properties
     *
     * @param statusHolders array of status holders
     * @param resource registry resource
     */
    private void populateStatusProperties(StatusHolder[] statusHolders, Resource resource) {
        if (statusHolders != null) {
            for (StatusHolder statusHolder : statusHolders) {
                if (statusHolder != null) {
                    List<String> list = new ArrayList<>();
                    list.add(statusHolder.getType());
                    list.add(statusHolder.getTimeInstance());
                    list.add(statusHolder.getUser());
                    list.add(statusHolder.getKey());
                    list.add(Boolean.toString(statusHolder.isSuccess()));
                    if (statusHolder.getMessage() != null) {
                        list.add(statusHolder.getMessage());
                    } else {
                        list.add("");
                    }
                    if (statusHolder.getTarget() != null) {
                        list.add(statusHolder.getTarget());
                    } else {
                        list.add("");
                    }
                    if (statusHolder.getTargetAction() != null) {
                        list.add(statusHolder.getTargetAction());
                    } else {
                        list.add("");
                    }
                    if (statusHolder.getVersion() != null) {
                        list.add(statusHolder.getVersion());
                    } else {
                        list.add("");
                    }
                    resource.setProperty(UUID.randomUUID().toString(), list);
                }
            }
        }
    }


    /**
     * Removes persisted status data
     *
     * @param path registry path
     * @throws EntitlementException throws, if fails
     */
    public synchronized void removeStatusData(String path) throws EntitlementException {

        Registry registry;
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            registry = EntitlementServiceComponent.getRegistryService().getGovernanceSystemRegistry(tenantId);
            if (registry.resourceExists(path)) {
                registry.delete(path);
            }
        } catch (RegistryException e) {
            log.error(e);
            throw new EntitlementException("Error while removing persisted status data", e);
        }
    }

}
