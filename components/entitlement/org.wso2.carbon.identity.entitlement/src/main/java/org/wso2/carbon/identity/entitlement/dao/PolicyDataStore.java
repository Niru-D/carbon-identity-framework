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
import org.wso2.balana.combine.PolicyCombiningAlgorithm;
import org.wso2.balana.combine.xacml3.DenyOverridesPolicyAlg;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.EntitlementUtil;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.PolicyStoreDTO;
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.identity.entitlement.pdp.EntitlementEngine;

import static org.wso2.carbon.identity.entitlement.PDPConstants.EntitlementTableColumns;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_POLICY_COMBINING_ALGORITHM_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_ALL_PDP_POLICY_DATA_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_POLICY_COMBINING_ALGORITHM_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PDP_POLICY_DATA_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.UPDATE_POLICY_COMBINING_ALGORITHM_SQL;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * This is default implementation
 */
public class PolicyDataStore implements PolicyDataStoreModule {

    public static final String POLICY_COMBINING_PREFIX_1 =
            "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:";
    public static final String POLICY_COMBINING_PREFIX_3 =
            "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:";
    private static Log log = LogFactory.getLog(PolicyDataStore.class);


    @Override
    public void init(Properties properties) throws EntitlementException {

    }

    @Override
    public PolicyCombiningAlgorithm getGlobalPolicyAlgorithm() {

        String algorithm = null;
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyCombiningAlgoPrepStmt = null;
        ResultSet rs = null;

        try {
            getPolicyCombiningAlgoPrepStmt = connection.prepareStatement(GET_POLICY_COMBINING_ALGORITHM_SQL);
            getPolicyCombiningAlgoPrepStmt.setInt(1, tenantId);
            getPolicyCombiningAlgoPrepStmt.setString(2, PDPConstants.GLOBAL_POLICY_COMBINING_ALGORITHM);
            rs = getPolicyCombiningAlgoPrepStmt.executeQuery();

            if(rs.next()){
                algorithm = rs.getString(EntitlementTableColumns.CONFIG_VALUE);
            }

            if (algorithm == null || algorithm.trim().length() == 0) {
                // read algorithm from entitlement.properties file
                algorithm = EntitlementServiceComponent.getEntitlementConfig().getEngineProperties().
                        getProperty(PDPConstants.PDP_GLOBAL_COMBINING_ALGORITHM);
                log.info("Using Global policy combining algorithm that is defined in configuration file.");
                try {
                    return EntitlementUtil.getPolicyCombiningAlgorithm(algorithm);
                } catch (Exception e) {
                    log.debug(e);
                }
            }

            if (algorithm != null && algorithm.trim().length() > 0) {
                if ("first-applicable".equals(algorithm) || "only-one-applicable".equals(algorithm)) {
                    algorithm = POLICY_COMBINING_PREFIX_1 + algorithm;
                } else {
                    algorithm = POLICY_COMBINING_PREFIX_3 + algorithm;
                }
                return EntitlementUtil.getPolicyCombiningAlgorithm(algorithm);
            }

        } catch (SQLException | EntitlementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while getting Global Policy Algorithm from policy data store.", e);
            }
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, getPolicyCombiningAlgoPrepStmt);
        }

        log.warn("Global policy combining algorithm is not defined. Therefore using default one");
        return new DenyOverridesPolicyAlg();
    }


    @Override
    public void setGlobalPolicyAlgorithm(String policyCombiningAlgorithm) throws EntitlementException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement getAlgoPresencePrepStmt = null;
        ResultSet rs = null;
        PreparedStatement setPolicyCombiningAlgoPrepStmt = null;

        try {
            //Check the existence of the algorithm
            getAlgoPresencePrepStmt = connection.prepareStatement(GET_POLICY_COMBINING_ALGORITHM_SQL);
            getAlgoPresencePrepStmt.setInt(1, tenantId);
            getAlgoPresencePrepStmt.setString(2, PDPConstants.GLOBAL_POLICY_COMBINING_ALGORITHM);
            rs = getAlgoPresencePrepStmt.executeQuery();

            if(rs.next()){
                //Update the algorithm
                setPolicyCombiningAlgoPrepStmt = connection.prepareStatement(UPDATE_POLICY_COMBINING_ALGORITHM_SQL);
            }else{
                //Insert the algorithm
                setPolicyCombiningAlgoPrepStmt = connection.prepareStatement(CREATE_POLICY_COMBINING_ALGORITHM_SQL);
            }
            setPolicyCombiningAlgoPrepStmt.setString(1, policyCombiningAlgorithm);
            setPolicyCombiningAlgoPrepStmt.setInt(2, tenantId);
            setPolicyCombiningAlgoPrepStmt.setString(3, PDPConstants.GLOBAL_POLICY_COMBINING_ALGORITHM);
            setPolicyCombiningAlgoPrepStmt.executeUpdate();

            // performing cache invalidation
            EntitlementEngine.getInstance().invalidatePolicyCache();

            IdentityDatabaseUtil.closeStatement(setPolicyCombiningAlgoPrepStmt);
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("Error while updating Global combing algorithm in policy store ", e);
            throw new EntitlementException("Error while updating combing algorithm in policy store");
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, getAlgoPresencePrepStmt);
        }
    }


    @Override
    public String getGlobalPolicyAlgorithmName() {

        String algorithm = null;
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyCombiningAlgoPrepStmt = null;
        ResultSet rs = null;

        try {

            getPolicyCombiningAlgoPrepStmt = connection.prepareStatement(GET_POLICY_COMBINING_ALGORITHM_SQL);
            getPolicyCombiningAlgoPrepStmt.setInt(1, tenantId);
            getPolicyCombiningAlgoPrepStmt.setString(2, PDPConstants.GLOBAL_POLICY_COMBINING_ALGORITHM);
            rs = getPolicyCombiningAlgoPrepStmt.executeQuery();

            if(rs.next()){
                algorithm = rs.getString(EntitlementTableColumns.CONFIG_VALUE);
            }

        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting Global Policy Combining Algorithm Name.", e);
            }
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, getPolicyCombiningAlgoPrepStmt);
        }

        // set default
        if (algorithm == null) {
            algorithm = "deny-overrides";
        }

        return algorithm;
    }


    @Override
    public String[] getAllGlobalPolicyAlgorithmNames() {

        return new String[]{"deny-overrides", "permit-overrides", "first-applicable",
                "ordered-deny-overrides", "ordered-permit-overrides", "only-one-applicable"};
    }


    @Override
    public PolicyStoreDTO getPolicyData(String policyId) {

        PolicyStoreDTO dataDTO = new PolicyStoreDTO();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getAllPolicyData= null;
        ResultSet policyData = null;

        try {
            getAllPolicyData = connection.prepareStatement(GET_PDP_POLICY_DATA_SQL);
            getAllPolicyData.setString(1, policyId);
            getAllPolicyData.setInt(2, 1);
            getAllPolicyData.setInt(3, tenantId);
            policyData = getAllPolicyData.executeQuery();

            if(policyData.next()){
                dataDTO.setPolicyOrder(policyData.getInt(EntitlementTableColumns.POLICY_ORDER));
                boolean active = policyData.getInt(EntitlementTableColumns.IS_ACTIVE) == 1;
                dataDTO.setActive(active);
                dataDTO.setPolicyType(policyData.getString(EntitlementTableColumns.POLICY_TYPE));
            }
            return dataDTO;

        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            log.error("Error while getting policy data for policyId: " + policyId, e);
            return dataDTO;
        }finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policyData, getAllPolicyData);
        }
    }


    @Override
    public PolicyStoreDTO[] getPolicyData() {

        List<PolicyStoreDTO> policyStoreDTOs = new ArrayList<PolicyStoreDTO>();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getAllPolicyData= null;
        ResultSet policyData = null;

        try {
            getAllPolicyData = connection.prepareStatement(GET_ALL_PDP_POLICY_DATA_SQL);
            getAllPolicyData.setInt(1, tenantId);
            getAllPolicyData.setInt(2, 1);
            policyData = getAllPolicyData.executeQuery();

            if(policyData.next()){
                do{
                    PolicyStoreDTO dataDTO = new PolicyStoreDTO();
                    dataDTO.setPolicyId(policyData.getString(EntitlementTableColumns.POLICY_ID));
                    dataDTO.setPolicyOrder(policyData.getInt(EntitlementTableColumns.POLICY_ORDER));
                    boolean active = (policyData.getInt(EntitlementTableColumns.IS_ACTIVE) == 1);
                    dataDTO.setActive(active);
                    dataDTO.setPolicyType(policyData.getString(EntitlementTableColumns.POLICY_TYPE));
                    policyStoreDTOs.add(dataDTO);
                } while(policyData.next());
            }
            return policyStoreDTOs.toArray(new PolicyStoreDTO[policyStoreDTOs.size()]);

        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
            log.error("Error while getting all policy data", e);
            return policyStoreDTOs.toArray(new PolicyStoreDTO[policyStoreDTOs.size()]);
        }finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policyData, getAllPolicyData);
        }
    }


}
