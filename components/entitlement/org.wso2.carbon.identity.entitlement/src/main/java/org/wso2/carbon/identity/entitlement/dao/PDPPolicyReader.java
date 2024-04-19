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
import org.wso2.balana.AbstractPolicy;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.PolicyOrderComparator;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.pap.PAPPolicyReader;
import org.wso2.carbon.identity.entitlement.policy.PolicyAttributeBuilder;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import static org.wso2.carbon.identity.entitlement.PDPConstants.EntitlementTableColumns;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_ALL_PDP_POLICIES_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_META_DATA_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_REFS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_SET_REFS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PDP_POLICY_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_POLICY_COMBINING_ALGORITHM_SQL;

/**
 * PDP policy reader
 */
public class PDPPolicyReader implements PDPPolicyReaderModule {

    /**
     * logger
     */
    private static final Log log = LogFactory.getLog(PDPPolicyReader.class);

    /**
     * constructor
     */
    public PDPPolicyReader() {

    }

    /**
     * Reads given policyId as PolicyDTO
     *
     * @param policyId policy id
     * @return PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    @Override
    public PolicyDTO readPolicy(String policyId) throws EntitlementException {

        PolicyDTO policy;
        policy = getPolicy(policyId);

        if (policy == null) {
            return new PolicyDTO();
        }

        return policy;
    }


    /**
     * Reads All ordered active policies as PolicyDTO
     *
     * @param active only return active policies
     * @param order  return ordered policy
     * @return Array of PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    @Override
    public PolicyDTO[] readAllPolicies(boolean active, boolean order) throws EntitlementException {

        PolicyDTO[] policies;
        policies = getAllPolicies();

        if (policies == null) {
            return new PolicyDTO[0];
        }
        List<PolicyDTO> policyDTOList = new ArrayList<>();
        for (PolicyDTO policy : policies) {
            if (active) {
                if (policy.isActive()) {
                    policyDTOList.add(policy);
                }
            } else {
                policyDTOList.add(policy);
            }
        }

        PolicyDTO[] policyDTOs = policyDTOList.toArray(new PolicyDTO[0]);

        if (order) {
            Arrays.sort(policyDTOs, new PolicyOrderComparator());
        }
        return policyDTOs;

    }


    /**
     * This returns all policy ids as a String list.
     *
     * @return policy ids as String[]
     * @throws EntitlementException throws if fails
     */
    @Override
    public String[] getAllPolicyIds() throws EntitlementException {

        List<String> policyIDs = new ArrayList<>();
        PolicyDTO[] policyDTOs;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        policyDTOs = getAllPolicies();
        assert policyDTOs != null;
        for (PolicyDTO dto : policyDTOs) {
            policyIDs.add(dto.getPolicyId());
        }

        return policyIDs.toArray(new String[0]);
    }


    /**
     * This reads the policy combining algorithm
     *
     * @return policy combining algorithm as String
     * @throws EntitlementException throws
     */
    @Override
    public String readPolicyCombiningAlgorithm() throws EntitlementException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyCombiningAlgoPrepStmt = null;
        ResultSet algorithm = null;

        try {
            getPolicyCombiningAlgoPrepStmt = connection.prepareStatement(GET_POLICY_COMBINING_ALGORITHM_SQL);
            getPolicyCombiningAlgoPrepStmt.setInt(1, tenantId);
            getPolicyCombiningAlgoPrepStmt.setString(2, PDPConstants.GLOBAL_POLICY_COMBINING_ALGORITHM);
            algorithm = getPolicyCombiningAlgoPrepStmt.executeQuery();

            if (algorithm.next()) {
                return algorithm.getString(EntitlementTableColumns.CONFIG_VALUE);
            } else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while reading policy combining algorithm", e);
            throw new EntitlementException("Error while reading policy combining algorithm", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, algorithm, getPolicyCombiningAlgoPrepStmt);
        }
    }


    /**
     * This returns given policy as a policy DTO
     *
     * @param policyId policy id
     * @return policyDTO
     * @throws EntitlementException throws, if fails
     */
    private PolicyDTO getPolicy(String policyId) throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving entitlement policy");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPDPPolicy = null;
        ResultSet policy = null;
        PolicyDTO dto = new PolicyDTO();

        try {

            getPDPPolicy = connection.prepareStatement(GET_PDP_POLICY_SQL);
            getPDPPolicy.setString(1, policyId);
            getPDPPolicy.setInt(2, 1);
            getPDPPolicy.setInt(3, tenantId);
            policy = getPDPPolicy.executeQuery();

            if (policy.next()) {
                String policyString = policy.getString(EntitlementTableColumns.POLICY);
                AbstractPolicy absPolicy = PAPPolicyReader.getInstance(null).getPolicy(policyString);
                dto.setPolicyId(absPolicy.getId().toASCIIString());
                dto.setPolicy(policyString);
                int policyOrder = policy.getInt(EntitlementTableColumns.POLICY_ORDER);
                dto.setPolicyOrder(policyOrder);
                int isActiveInt = policy.getInt(EntitlementTableColumns.IS_ACTIVE);
                dto.setActive((isActiveInt != 0));
                dto.setPolicyType(policy.getString(EntitlementTableColumns.POLICY_TYPE));

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt = connection.prepareStatement(
                        GET_PAP_POLICY_META_DATA_SQL,
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
                getPolicyMetaDataPrepStmt.setString(1, absPolicy.getId().toASCIIString());
                getPolicyMetaDataPrepStmt.setInt(2, policy.getInt(EntitlementTableColumns.VERSION));
                getPolicyMetaDataPrepStmt.setInt(3, tenantId);
                ResultSet metadata = getPolicyMetaDataPrepStmt.executeQuery();

                int metaDataAmount = 0;
                if (metadata != null) {
                    metadata.last();
                    metaDataAmount = metadata.getRow();
                    metadata.beforeFirst();
                }

                Properties properties = new Properties();
                for (int i = 0; i < metaDataAmount; i++) {
                    metadata.beforeFirst();
                    while (metadata.next()) {
                        if (Objects.equals(metadata.getString(EntitlementTableColumns.ATTRIBUTE_NAME),
                                PDPConstants.POLICY_META_DATA + i)) {
                            properties.setProperty(PDPConstants.POLICY_META_DATA + i,
                                    metadata.getString(EntitlementTableColumns.ATTRIBUTE_VALUE));
                            break;
                        }
                    }
                }

                PolicyAttributeBuilder policyAttributeBuilder = new PolicyAttributeBuilder();
                dto.setAttributeDTOs(policyAttributeBuilder.getPolicyMetaData(properties));

                IdentityDatabaseUtil.closeResultSet(metadata);
                IdentityDatabaseUtil.closeStatement(getPolicyMetaDataPrepStmt);

            } else {
                return null;
            }
            return dto;

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy : " + policyId, e);
            throw new EntitlementException("Error while retrieving entitlement policy : " + policyId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policy, getPDPPolicy);
        }
    }


    /**
     * This returns all the policies as PolicyDTOs.
     *
     * @return policies as PolicyDTO[]
     * @throws EntitlementException throws if fails
     */
    private PolicyDTO[] getAllPolicies() throws EntitlementException {

        List<PolicyDTO> policies = new ArrayList<>();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getAllPDPPolicies = null;
        ResultSet policySet = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        try {

            getAllPDPPolicies = connection.prepareStatement(GET_ALL_PDP_POLICIES_SQL);
            getAllPDPPolicies.setInt(1, tenantId);
            getAllPDPPolicies.setInt(2, 1);
            policySet = getAllPDPPolicies.executeQuery();

            if (policySet.next()) {
                do {
                    String policy = policySet.getString(EntitlementTableColumns.POLICY);
                    AbstractPolicy absPolicy = PAPPolicyReader.getInstance(null).getPolicy(policy);
                    PolicyDTO dto = new PolicyDTO();
                    dto.setPolicyId(absPolicy.getId().toASCIIString());
                    dto.setPolicy(policy);
                    int policyOrder = policySet.getInt(EntitlementTableColumns.POLICY_ORDER);
                    dto.setPolicyOrder(policyOrder);
                    int isActiveInt = policySet.getInt(EntitlementTableColumns.IS_ACTIVE);
                    dto.setActive((isActiveInt != 0));
                    dto.setPolicyType(policySet.getString(EntitlementTableColumns.POLICY_TYPE));

                    //Get policy references
                    List<String> policyReferences = new ArrayList<>();
                    PreparedStatement getPolicyRefsPrepStmt = connection.prepareStatement(GET_PAP_POLICY_REFS_SQL);
                    getPolicyRefsPrepStmt.setInt(1, tenantId);
                    getPolicyRefsPrepStmt.setString(2, absPolicy.getId().toASCIIString());
                    getPolicyRefsPrepStmt.setInt(3, policySet.getInt(EntitlementTableColumns.VERSION));
                    ResultSet policyRefs = getPolicyRefsPrepStmt.executeQuery();

                    if (policyRefs.next()) {
                        do {
                            policyReferences.add(policyRefs.getString(EntitlementTableColumns.REFERENCE));
                        } while (policyRefs.next());
                    }
                    dto.setPolicyIdReferences(policyReferences.toArray(new String[0]));
                    IdentityDatabaseUtil.closeResultSet(policyRefs);
                    IdentityDatabaseUtil.closeStatement(getPolicyRefsPrepStmt);

                    //Get policy set references
                    List<String> policySetReferences = new ArrayList<>();
                    PreparedStatement getPolicySetRefsPrepStmt = connection.prepareStatement(GET_PAP_POLICY_SET_REFS_SQL);
                    getPolicySetRefsPrepStmt.setInt(1, tenantId);
                    getPolicySetRefsPrepStmt.setString(2, absPolicy.getId().toASCIIString());
                    getPolicySetRefsPrepStmt.setInt(3, policySet.getInt(EntitlementTableColumns.VERSION));
                    ResultSet policySetRefs = getPolicySetRefsPrepStmt.executeQuery();

                    if (policySetRefs.next()) {
                        do {
                            policySetReferences.add(policySetRefs.getString(EntitlementTableColumns.SET_REFERENCE));
                        } while (policySetRefs.next());
                    }
                    dto.setPolicySetIdReferences(policySetReferences.toArray(new String[0]));
                    IdentityDatabaseUtil.closeResultSet(policySetRefs);
                    IdentityDatabaseUtil.closeStatement(getPolicySetRefsPrepStmt);

                    //Get policy metadata
                    PreparedStatement getPolicyMetaDataPrepStmt = connection.prepareStatement(
                            GET_PAP_POLICY_META_DATA_SQL,
                            ResultSet.TYPE_SCROLL_INSENSITIVE,
                            ResultSet.CONCUR_READ_ONLY
                    );
                    getPolicyMetaDataPrepStmt.setString(1, absPolicy.getId().toASCIIString());
                    getPolicyMetaDataPrepStmt.setInt(2, policySet.getInt(EntitlementTableColumns.VERSION));
                    getPolicyMetaDataPrepStmt.setInt(3, tenantId);
                    ResultSet metadata = getPolicyMetaDataPrepStmt.executeQuery();

                    int metaDataAmount = 0;
                    if (metadata != null) {
                        metadata.last();
                        metaDataAmount = metadata.getRow();
                        metadata.beforeFirst();
                    }

                    Properties properties = new Properties();
                    for (int i = 0; i < metaDataAmount; i++) {
                        metadata.beforeFirst();
                        while (metadata.next()) {
                            if (Objects.equals(metadata.getString(EntitlementTableColumns.ATTRIBUTE_NAME),
                                    PDPConstants.POLICY_META_DATA + i)) {
                                properties.setProperty(PDPConstants.POLICY_META_DATA + i,
                                        metadata.getString(EntitlementTableColumns.ATTRIBUTE_VALUE));
                                break;
                            }
                        }
                    }

                    PolicyAttributeBuilder policyAttributeBuilder = new PolicyAttributeBuilder();
                    dto.setAttributeDTOs(policyAttributeBuilder.getPolicyMetaData(properties));

                    IdentityDatabaseUtil.closeResultSet(metadata);
                    IdentityDatabaseUtil.closeStatement(getPolicyMetaDataPrepStmt);

                    policies.add(dto);

                } while (policySet.next());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to access an entitlement policy which does not exist");
                }
                return null;
            }

            return policies.toArray(new PolicyDTO[0]);

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy", e);
            throw new EntitlementException("Error while retrieving entitlement policies", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policySet, getAllPDPPolicies);
        }
    }

}
