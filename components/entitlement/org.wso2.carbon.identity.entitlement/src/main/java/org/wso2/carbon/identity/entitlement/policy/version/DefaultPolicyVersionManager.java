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
package org.wso2.carbon.identity.entitlement.policy.version;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.identity.entitlement.pap.store.PAPPolicyStore;
import org.wso2.carbon.identity.entitlement.pap.store.PAPPolicyStoreManager;
import org.wso2.carbon.identity.entitlement.pap.store.PAPPolicyStoreReader;
import org.wso2.carbon.registry.api.Collection;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.ResourceNotFoundException;
import org.wso2.carbon.registry.core.utils.RegistryUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 *
 */
public class DefaultPolicyVersionManager implements PolicyVersionManager {


    private static Log log = LogFactory.getLog(DefaultPolicyVersionManager.class);

    private static int DEFAULT_MAX_VERSION = 5;

    private int maxVersions;

    @Override
    public void init(Properties properties) {
        try {
            maxVersions = Integer.parseInt(properties.getProperty("maxVersions"));
        } catch (Exception e) {
            // ignore
        }
        if (maxVersions == 0) {
            maxVersions = DEFAULT_MAX_VERSION;
        }
    }

    @Override
    public PolicyDTO getPolicy(String policyId, String version) throws EntitlementException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        // Zero means current version
        if (version == null || version.trim().length() == 0) {
//            Registry registry = EntitlementServiceComponent.
//                    getGovernanceRegistry(CarbonContext.getThreadLocalCarbonContext().getTenantId());
            PreparedStatement getLatestVersionPrepStmt = null;
            ResultSet latestVersion = null;

            try {
//                Collection collection = (Collection) registry.
//                        get(PDPConstants.ENTITLEMENT_POLICY_VERSION + policyId);
//                if (collection != null) {
//                    version = collection.getProperty("version");
//                }
                getLatestVersionPrepStmt = connection.prepareStatement(
                        "SELECT MAX(VERSION) AS VERSION FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND TENANT_ID=?" +
                                " AND IS_IN_PAP=?");
                getLatestVersionPrepStmt.setString(1, policyId);
                getLatestVersionPrepStmt.setInt(2, tenantId);
                getLatestVersionPrepStmt.setInt(3, 1);
                latestVersion = getLatestVersionPrepStmt.executeQuery();

                if(latestVersion.next()){
                    version = String.valueOf(latestVersion.getInt("VERSION"));
                }

            } catch (SQLException e) {
                log.error(e);
                throw new EntitlementException("Invalid policy version");
            }finally {
                IdentityDatabaseUtil.closeAllConnections(connection, latestVersion, getLatestVersionPrepStmt);
            }
        }

        PAPPolicyStore policyStore = new PAPPolicyStore();
        PAPPolicyStoreReader reader = new PAPPolicyStoreReader(policyStore);

        PolicyDTO dto = policyStore.getPolicyByVersion(policyId, version);
        if (dto == null) {
            throw new EntitlementException("No policy with the given policyID and version");
        }
        return dto;
//        return reader.readPolicyDTO(resource);
    }

    @Override
    public String createVersion(PolicyDTO policyDTO) throws EntitlementException {

        PAPPolicyStoreManager manager = new PAPPolicyStoreManager();
//        Registry registry = EntitlementServiceComponent.
//                getGovernanceRegistry(CarbonContext.getThreadLocalCarbonContext().getTenantId());

        String version = "0";

        //            Collection collection = null;
//            try {
//                collection = (Collection) registry.
//                        get(PDPConstants.ENTITLEMENT_POLICY_VERSION + policyDTO.getPolicyId());
//            } catch (ResourceNotFoundException e) {
//                // ignore
//            }
        if(manager.isExistPolicy(policyDTO.getPolicyId())){
            PolicyDTO dto = manager.getLightPolicy(policyDTO.getPolicyId());
            version = dto.getVersion();
        }

//            if (collection != null) {
//                version = collection.getProperty("version");
//            } else {
//                collection = registry.newCollection();
//                collection.setProperty("version", "1");
//                registry.put(PDPConstants.ENTITLEMENT_POLICY_VERSION +
//                        policyDTO.getPolicyId(), collection);
//            }

        int versionInt = Integer.parseInt(version);
//            String policyPath = PDPConstants.ENTITLEMENT_POLICY_VERSION +
//                    policyDTO.getPolicyId() + RegistryConstants.PATH_SEPARATOR;

        // check whether this is larger than max version
        if (versionInt > maxVersions) {
            // delete the older version
            int olderVersion = versionInt - maxVersions;
//                if (registry.resourceExists(policyPath + olderVersion)) {
//                    registry.delete(policyPath + olderVersion);
//                }
            manager.removePolicyByVersion(policyDTO.getPolicyId(), olderVersion);
        }

        //new version
        version = Integer.toString(versionInt + 1);

//            // set version properties
//            policyDTO.setVersion(version);
//
//            // persist new version
//            policyStore.addOrUpdatePolicy(policyDTO, version, policyPath);

//            // set new version
//            collection.setProperty("version", version);
//            registry.put(PDPConstants.ENTITLEMENT_POLICY_VERSION +
//                    policyDTO.getPolicyId(), collection);
        return version;
    }


    @Override
    public void deletePolicy(String policyId) throws EntitlementException {
        //TODO remove this method
        Registry registry = EntitlementServiceComponent.
                getGovernanceRegistry(CarbonContext.getThreadLocalCarbonContext().getTenantId());
        try {
            if (registry.resourceExists(PDPConstants.ENTITLEMENT_POLICY_VERSION + policyId)) {
                registry.delete(PDPConstants.ENTITLEMENT_POLICY_VERSION + policyId);
            }
        } catch (RegistryException e) {
            log.error("Error while deleting all versions of policy", e);
        }
    }

    @Override
    public String[] getVersions(String policyId) throws EntitlementException {

//        List<String> versions = new ArrayList<String>();
//        Registry registry = EntitlementServiceComponent.
//                getGovernanceRegistry(CarbonContext.getThreadLocalCarbonContext().getTenantId());
//        Collection collection = null;
//        try {
//            try {
//                collection = (Collection) registry.
//                        get(PDPConstants.ENTITLEMENT_POLICY_VERSION + policyId);
//            } catch (ResourceNotFoundException e) {
//                // ignore
//            }
//            if (collection != null && collection.getChildren() != null) {
//                String[] children = collection.getChildren();
//                for (String child : children) {
//                    versions.add(RegistryUtils.getResourceName(child));
//                }
//            }
//        } catch (RegistryException e) {
//            log.error("Error while creating new version of policy", e);
//        }
//        return versions.toArray(new String[versions.size()]);

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        List<String> versions = new ArrayList<String>();
        PreparedStatement getVersionsPrepStmt = null;
        ResultSet versionsSet = null;

        try{
            getVersionsPrepStmt = connection.prepareStatement(
                    "SELECT VERSION FROM IDN_XACML_POLICY WHERE TENANT_ID=? AND POLICY_ID=?");
            getVersionsPrepStmt.setInt(1, tenantId);
            getVersionsPrepStmt.setString(2, policyId);
            versionsSet = getVersionsPrepStmt.executeQuery();

            while (versionsSet.next()){
                versions.add(String.valueOf(versionsSet.getInt("VERSION")));
            }

        } catch (SQLException e){
            log.error("Error while retrieving policy versions", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, versionsSet, getVersionsPrepStmt);
        }
        return versions.toArray(new String[versions.size()]);
    }
}
