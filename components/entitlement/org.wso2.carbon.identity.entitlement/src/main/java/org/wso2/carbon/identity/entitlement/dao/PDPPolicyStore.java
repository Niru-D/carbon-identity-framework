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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.dto.AttributeDTO;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.dto.PolicyStoreDTO;
import org.wso2.carbon.identity.entitlement.policy.finder.AbstractPolicyFinderModule;
import org.wso2.carbon.identity.entitlement.policy.finder.PolicyFinderModule;

import static org.wso2.carbon.identity.entitlement.PDPConstants.EntitlementTableColumns;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_PUBLISHED_VERSIONS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_UNUSED_POLICY_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_ACTIVE_STATUS_AND_ORDER_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_POLICY_PDP_PRESENCE_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PUBLISHED_POLICY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.PUBLISH_POLICY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.RESTORE_ACTIVE_STATUS_AND_ORDER_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.UPDATE_ACTIVE_STATUS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.UPDATE_ORDER_SQL;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 *
 */
public class PDPPolicyStore extends AbstractPolicyFinderModule
        implements PDPPolicyStoreModule {

    //TODO
    private static final String MODULE_NAME = "Registry Policy Finder Module";
    private static Log log = LogFactory.getLog(PDPPolicyStore.class);

    @Override
    public void init(Properties properties) {

    }

    @Override
    public void addPolicy(PolicyStoreDTO policy) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (policy == null || StringUtils.isBlank(policy.getPolicyId())) {
            throw new EntitlementException("Policy can not be null");
        }

        try {

            int active;
            int order;
            int version = 0;
            int previousActive = 0;
            int previousOrder = 0;

            //Get published version
            if (policy.getVersion() == null) {
                try (PreparedStatement getPublishedVersionPrepStmt =
                             connection.prepareStatement(GET_PUBLISHED_POLICY_VERSION_SQL)) {
                    getPublishedVersionPrepStmt.setString(1, policy.getPolicyId());
                    getPublishedVersionPrepStmt.setInt(2, tenantId);
                    getPublishedVersionPrepStmt.setInt(3, 1);
                    try (ResultSet rs = getPublishedVersionPrepStmt.executeQuery()) {
                        if (rs.next()) {
                            version = rs.getInt(EntitlementTableColumns.VERSION);
                        } else {
                            throw new SQLException("No published version found for policy: " + policy.getPolicyId());
                        }
                        IdentityDatabaseUtil.closeResultSet(rs);
                    }
                    IdentityDatabaseUtil.closeStatement(getPublishedVersionPrepStmt);
                }
            } else {
                version = Integer.parseInt(policy.getVersion());
            }


            //Update active status
            if (policy.isSetActive()) {
                active = policy.isActive() ? 1 : 0;
                PreparedStatement updateActiveStatusPrepStmt = connection.prepareStatement(UPDATE_ACTIVE_STATUS_SQL);
                updateActiveStatusPrepStmt.setInt(1, active);
                updateActiveStatusPrepStmt.setString(2, policy.getPolicyId());
                updateActiveStatusPrepStmt.setInt(3, tenantId);
                updateActiveStatusPrepStmt.setInt(4, version);
                updateActiveStatusPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(updateActiveStatusPrepStmt);
            }

            //Update order
            if (policy.isSetOrder()) {
                if (policy.getPolicyOrder() > 0) {
                    order = policy.getPolicyOrder();
                    PreparedStatement updateOrderPrepStmt = connection.prepareStatement(UPDATE_ORDER_SQL);
                    updateOrderPrepStmt.setInt(1, order);
                    updateOrderPrepStmt.setString(2, policy.getPolicyId());
                    updateOrderPrepStmt.setInt(3, tenantId);
                    updateOrderPrepStmt.setInt(4, version);
                    updateOrderPrepStmt.executeUpdate();
                    IdentityDatabaseUtil.closeStatement(updateOrderPrepStmt);
                }
            }

            if(!policy.isSetActive() && !policy.isSetOrder()){

                //Get active status and order of the previously published policy version
                PreparedStatement getActiveStatusAndOrderPrepStmt =
                        connection.prepareStatement(GET_ACTIVE_STATUS_AND_ORDER_SQL);
                getActiveStatusAndOrderPrepStmt.setString(1, policy.getPolicyId());
                getActiveStatusAndOrderPrepStmt.setInt(2, tenantId);
                getActiveStatusAndOrderPrepStmt.setInt(3, 1);
                ResultSet rs = getActiveStatusAndOrderPrepStmt.executeQuery();

                if(rs.next()){
                    previousActive = rs.getInt(EntitlementTableColumns.IS_ACTIVE);
                    previousOrder = rs.getInt(EntitlementTableColumns.POLICY_ORDER);
                }
                IdentityDatabaseUtil.closeResultSet(rs);
                IdentityDatabaseUtil.closeStatement(getActiveStatusAndOrderPrepStmt);

                //Remove previously published versions of the policy
                PreparedStatement updatePublishStatusPrepStmt =
                        connection.prepareStatement(DELETE_PUBLISHED_VERSIONS_SQL);
                updatePublishStatusPrepStmt.setInt(1, 0);
                updatePublishStatusPrepStmt.setInt(2, 0);
                updatePublishStatusPrepStmt.setInt(3, 0);
                updatePublishStatusPrepStmt.setString(4, policy.getPolicyId());
                updatePublishStatusPrepStmt.setInt(5, tenantId);
                updatePublishStatusPrepStmt.setInt(6, 1);
                updatePublishStatusPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(updatePublishStatusPrepStmt);

                //When removing previously published versions,
                // If the policy has been already removed from PAP, remove the policy from the database
                PreparedStatement removePolicyPrepStmt = connection.prepareStatement(DELETE_UNUSED_POLICY_SQL);
                removePolicyPrepStmt.setString(1, policy.getPolicyId());
                removePolicyPrepStmt.setInt(2, tenantId);
                removePolicyPrepStmt.setInt(3, 0);
                removePolicyPrepStmt.setInt(4, 0);
                removePolicyPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyPrepStmt);
            }

            //Publish the given version of the policy
            PreparedStatement publishPolicyPrepStmt = connection.prepareStatement(PUBLISH_POLICY_VERSION_SQL);
            publishPolicyPrepStmt.setInt(1, 1);
            publishPolicyPrepStmt.setString(2, policy.getPolicyId());
            publishPolicyPrepStmt.setInt(3, tenantId);
            publishPolicyPrepStmt.setInt(4, version);
            publishPolicyPrepStmt.executeUpdate();
            IdentityDatabaseUtil.closeStatement(publishPolicyPrepStmt);

            //If this is an update, keep the previous active status and order
            if(!policy.isSetActive() && !policy.isSetOrder()){
                PreparedStatement updatePolicyStatusAndOrderPrepStmt =
                        connection.prepareStatement(RESTORE_ACTIVE_STATUS_AND_ORDER_SQL);
                updatePolicyStatusAndOrderPrepStmt.setInt(1, previousActive);
                updatePolicyStatusAndOrderPrepStmt.setInt(2, previousOrder);
                updatePolicyStatusAndOrderPrepStmt.setString(3, policy.getPolicyId());
                updatePolicyStatusAndOrderPrepStmt.setInt(4, tenantId);
                updatePolicyStatusAndOrderPrepStmt.setInt(5, version);
                updatePolicyStatusAndOrderPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(updatePolicyStatusAndOrderPrepStmt);
            }

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("Error while publishing policy", e);
            throw new EntitlementException("Error while publishing policy", e);
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    @Override
    public boolean isPolicyExist(String policyId) {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (policyId == null || policyId.trim().isEmpty()) {
            return false;
        }

        PreparedStatement getPolicyPublishStatus = null;
        ResultSet rs = null;

        try {
            getPolicyPublishStatus = connection.prepareStatement(GET_POLICY_PDP_PRESENCE_SQL);
            getPolicyPublishStatus.setString(1,policyId);
            getPolicyPublishStatus.setInt(2, 1);
            getPolicyPublishStatus.setInt(3, tenantId);
            rs = getPolicyPublishStatus.executeQuery();

            return rs.next();

        } catch (SQLException e) {
            return false;
        }finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, getPolicyPublishStatus);
        }
    }

    @Override
    public void updatePolicy(PolicyStoreDTO policy) throws EntitlementException {
        addPolicy(policy);
    }


    @Override
    public boolean deletePolicy(String policyIdentifier) {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (policyIdentifier == null || policyIdentifier.trim().isEmpty()) {
            return false;
        }

        try {
            //Remove the published state of the given policy (Remove from PDP)
            PreparedStatement demotePolicyPrepStmt = connection.prepareStatement(DELETE_PUBLISHED_VERSIONS_SQL);
            demotePolicyPrepStmt.setInt(1, 0);
            demotePolicyPrepStmt.setInt(2, 0);
            demotePolicyPrepStmt.setInt(3, 0);
            demotePolicyPrepStmt.setString(4, policyIdentifier);
            demotePolicyPrepStmt.setInt(5, tenantId);
            demotePolicyPrepStmt.setInt(6, 1);
            demotePolicyPrepStmt.executeUpdate();
            IdentityDatabaseUtil.closeStatement(demotePolicyPrepStmt);

            //If the policy has been already removed from PAP, remove the policy from the database
            PreparedStatement removePolicyPrepStmt = connection.prepareStatement(DELETE_UNUSED_POLICY_SQL);
            removePolicyPrepStmt.setString(1, policyIdentifier);
            removePolicyPrepStmt.setInt(2, tenantId);
            removePolicyPrepStmt.setInt(3, 0);
            removePolicyPrepStmt.setInt(4, 0);
            removePolicyPrepStmt.executeUpdate();
            IdentityDatabaseUtil.closeStatement(removePolicyPrepStmt);

            IdentityDatabaseUtil.commitTransaction(connection);
            return true;

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error(e);
            return false;
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    @Override
    public String getModuleName() {
        return MODULE_NAME;
    }

    @Override
    public String getPolicy(String policyId) {
        PolicyDTO dto;
        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            dto = policyReaderModule.readPolicy(policyId);
            return dto.getPolicy();
        } catch (Exception e) {
            log.error("Policy with identifier " + policyId + " can not be retrieved " +
                      "from the policy finder module", e);
        }
        return null;
    }

    @Override
    public int getPolicyOrder(String policyId) {
        PolicyDTO dto;
        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            dto = policyReaderModule.readPolicy(policyId);
            return dto.getPolicyOrder();
        } catch (Exception e) {
            log.error("Policy with identifier " + policyId + " can not be retrieved " +
                      "from the policy finder module", e);
        }
        return -1;
    }

    @Override
    public String[] getActivePolicies() {

        log.debug("Retrieving of Active policies is started. " + new Date());

        List<String> policies = new ArrayList<String>();

        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            PolicyDTO[] policyDTOs = policyReaderModule.readAllPolicies(true, true);
            for (PolicyDTO dto : policyDTOs) {
                if (dto.getPolicy() != null) {
                    policies.add(dto.getPolicy());
                }
            }
        } catch (Exception e) {
            log.error("Policies can not be retrieved from the policy finder module", e);
        }

        log.debug("Retrieving of Active policies is finished.   " + new Date());

        return policies.toArray(new String[policies.size()]);
    }


    @Override
    public String[] getOrderedPolicyIdentifiers() {

        log.debug("Retrieving of Ordered Policy Ids is started. " + new Date());

        List<String> policies = new ArrayList<String>();

        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            PolicyDTO[] policyDTOs = policyReaderModule.readAllPolicies(false, true);
            for (PolicyDTO dto : policyDTOs) {
                if (dto.getPolicy() != null) {
                    policies.add(dto.getPolicyId());
                }
            }
        } catch (Exception e) {
            log.error("Policies can not be retrieved from the policy finder module", e);
        }

        log.debug("Retrieving of Ordered Policy Ids is finished. " + new Date());

        return policies.toArray(new String[policies.size()]);

    }

    @Override
    public String[] getPolicyIdentifiers() {
        String[] policyIds = null;
        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            policyIds = policyReaderModule.getAllPolicyIds();
        } catch (Exception e) {
            log.error("Policy identifiers can not be retrieved from the policy finder module", e);
        }
        return policyIds;
    }

    @Override
    public String getReferencedPolicy(String policyId) {

        // retrieve policies that are not active
        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            PolicyDTO dto = policyReaderModule.readPolicy(policyId);
            if (dto != null && dto.getPolicy() != null && !dto.isActive()) {
                return dto.getPolicy();
            }
        } catch (EntitlementException e) {
            log.error("Error while retrieving reference policy " + policyId);
            // ignore
        }

        return null;
    }

    @Override
    public Map<String, Set<AttributeDTO>> getSearchAttributes(String identifier, Set<AttributeDTO> givenAttribute) {

        PolicyDTO[] policyDTOs = null;
        Map<String, Set<AttributeDTO>> attributeMap = null;
        try {
            PDPPolicyReaderModule policyReaderModule = new PDPPolicyReader();
            policyDTOs = policyReaderModule.readAllPolicies(true, true);
        } catch (Exception e) {
            log.error("Policies can not be retrieved from the policy finder module", e);
        }

        if (policyDTOs != null) {
            attributeMap = new HashMap<String, Set<AttributeDTO>>();
            for (PolicyDTO policyDTO : policyDTOs) {
                Set<AttributeDTO> attributeDTOs =
                        new HashSet<AttributeDTO>(Arrays.asList(policyDTO.getAttributeDTOs()));
                String[] policyIdRef = policyDTO.getPolicyIdReferences();
                String[] policySetIdRef = policyDTO.getPolicySetIdReferences();

                if (policyIdRef != null && policyIdRef.length > 0 || policySetIdRef != null &&
                                                                     policySetIdRef.length > 0) {
                    for (PolicyDTO dto : policyDTOs) {
                        if (policyIdRef != null) {
                            for (String policyId : policyIdRef) {
                                if (dto.getPolicyId().equals(policyId)) {
                                    attributeDTOs.addAll(Arrays.asList(dto.getAttributeDTOs()));
                                }
                            }
                        }
                        for (String policySetId : policySetIdRef) {
                            if (dto.getPolicyId().equals(policySetId)) {
                                attributeDTOs.addAll(Arrays.asList(dto.getAttributeDTOs()));
                            }
                        }
                    }
                }
                attributeMap.put(policyDTO.getPolicyId(), attributeDTOs);
            }
        }

        return attributeMap;
    }


    @Override
    public int getSupportedSearchAttributesScheme() {
        return PolicyFinderModule.COMBINATIONS_BY_CATEGORY_AND_PARAMETER;
    }

    @Override
    public boolean isDefaultCategoriesSupported() {
        return true;
    }


    @Override
    public boolean isPolicyOrderingSupport() {
        return true;
    }

    @Override
    public boolean isPolicyDeActivationSupport() {
        return true;
    }
}
