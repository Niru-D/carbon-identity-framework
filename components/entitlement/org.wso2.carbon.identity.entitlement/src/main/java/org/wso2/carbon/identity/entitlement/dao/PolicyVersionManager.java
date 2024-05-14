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
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.pap.store.PAPPolicyStoreManager;

import static org.wso2.carbon.identity.entitlement.PDPConstants.EntitlementTableColumns;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_LATEST_POLICY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_POLICY_VERSIONS_SQL;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * This manages policy versions
 */
public class PolicyVersionManager implements PolicyVersionManagerModule {


    private static final Log log = LogFactory.getLog(PolicyVersionManager.class);

    private int maxVersions;


    /**
     * init policy version handler
     *
     * @param properties properties
     */
    @Override
    public void init(Properties properties) {
        try {
            maxVersions = Integer.parseInt(properties.getProperty("maxVersions"));
        } catch (Exception e) {
            // ignore
        }
        if (maxVersions == 0) {
            maxVersions = PDPConstants.DEFAULT_MAX_POLICY_VERSION;
        }
    }


//    /**
//     * Returns requested policy version
//     *
//     * @param policyId policyId
//     * @param version  policy version
//     * @return policyDTO
//     * @throws EntitlementException throws, if fails
//     */
//    @Override
//    public PolicyDTO getPolicy(String policyId, String version) throws EntitlementException {
//
//        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
//        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
//
//        // Zero means current version
//        if (version == null || version.trim().isEmpty()) {
//
//            PreparedStatement getLatestVersionPrepStmt = null;
//            ResultSet latestVersion = null;
//            try {
//                getLatestVersionPrepStmt = connection.prepareStatement(GET_LATEST_POLICY_VERSION_SQL);
//                getLatestVersionPrepStmt.setString(1, policyId);
//                getLatestVersionPrepStmt.setInt(2, tenantId);
//                getLatestVersionPrepStmt.setInt(3, 1);
//                latestVersion = getLatestVersionPrepStmt.executeQuery();
//
//                if (latestVersion.next()) {
//                    version = String.valueOf(latestVersion.getInt(EntitlementTableColumns.VERSION));
//                }
//
//            } catch (SQLException e) {
//                log.error(e);
//                throw new EntitlementException("Invalid policy version");
//            } finally {
//                IdentityDatabaseUtil.closeAllConnections(connection, latestVersion, getLatestVersionPrepStmt);
//            }
//        }
//
//        PAPPolicyStore policyStore = new PAPPolicyStore();
//        PolicyDTO dto;
//        dto = policyStore.getPolicy(policyId, version);
//
//        if (dto == null) {
//            throw new EntitlementException("No policy with the given policyID and version");
//        }
//        return dto;
//
//    }


    /**
     * Returns versions of the given policy
     *
     * @param policyId policyId
     * @return String[] of policy versions
     */
    @Override
    public String[] getVersions(String policyId) {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        List<String> versions = new ArrayList<>();
        PreparedStatement getVersionsPrepStmt = null;
        ResultSet versionsSet = null;

        try {
            getVersionsPrepStmt = connection.prepareStatement(GET_POLICY_VERSIONS_SQL);
            getVersionsPrepStmt.setInt(1, tenantId);
            getVersionsPrepStmt.setString(2, policyId);
            versionsSet = getVersionsPrepStmt.executeQuery();

            while (versionsSet.next()) {
                versions.add(String.valueOf(versionsSet.getInt(EntitlementTableColumns.VERSION)));
            }

        } catch (SQLException e) {
            log.error("Error while retrieving policy versions", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, versionsSet, getVersionsPrepStmt);
        }
        return versions.toArray(new String[0]);
    }


//    /**
//     * Creates policy versions
//     *
//     * @param policyDTO policyDTO
//     * @return version
//     * @throws EntitlementException throws, if fails
//     */
//    @Override
//    public String createVersion(PolicyDTO policyDTO) throws EntitlementException {
//
//        PAPPolicyStoreManager manager = new PAPPolicyStoreManager();
//        String version = "0";
//
//        if (manager.isExistPolicy(policyDTO.getPolicyId())) {
//            PolicyDTO dto = manager.getLightPolicy(policyDTO.getPolicyId());
//            version = dto.getVersion();
//        }
//
//        int versionInt = Integer.parseInt(version);
//
//        // check whether this is larger than max version
//        if (versionInt > maxVersions) {
//            // delete the older version
//            int olderVersion = versionInt - maxVersions;
//            manager.removePolicyByVersion(policyDTO.getPolicyId(), olderVersion);
//        }
//
//        //new version
//        version = Integer.toString(versionInt + 1);
//        return version;
//    }


    /**
     * Removes policy versions
     *
     * @param policyId policy id
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void deletePolicy(String policyId) throws EntitlementException {

    }

}
