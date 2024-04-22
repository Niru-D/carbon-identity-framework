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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.policy.PolicyAttributeBuilder;

import javax.xml.stream.XMLStreamException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import static org.wso2.carbon.identity.entitlement.PDPConstants.EntitlementTableColumns;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_PAP_POLICY_ATTRIBUTES_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_PAP_POLICY_EDITOR_DATA_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_PAP_POLICY_REFS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_PAP_POLICY_SET_REFS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_PAP_POLICY_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_PAP_POLICY_BY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_PAP_POLICY_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_POLICY_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_POLICY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_UNPUBLISHED_POLICY_VERSIONS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_ALL_PAP_POLICIES_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_BY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_EDITOR_DATA_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_IDS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_META_DATA_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_REFS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_SET_REFS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_PAP_POLICY_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_POLICY_PDP_PRESENCE_BY_VERSION_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_POLICY_PDP_PRESENCE_SQL;


public class PAPPolicyStore implements PAPPolicyStoreModule {

    // The logger we'll use for all messages
    private static final Log log = LogFactory.getLog(PAPPolicyStore.class);


    public PAPPolicyStore() {

    }


    /**
     * Returns all policy ids as String list.
     *
     * @return policy ids as a string list
     * @throws EntitlementException throws if fails
     */
    @Override
    public String[] getAllPolicyIds() throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policy IDs");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        List<String> policies = new ArrayList<>();
        PreparedStatement getPolicyIdsPrepStmt = null;
        ResultSet policyIds = null;

        try {
            getPolicyIdsPrepStmt = connection.prepareStatement(GET_PAP_POLICY_IDS_SQL);
            getPolicyIdsPrepStmt.setInt(1, tenantId);
            getPolicyIdsPrepStmt.setInt(2, 1);
            policyIds = getPolicyIdsPrepStmt.executeQuery();

            if (policyIds.next()) {
                do {
                    policies.add(policyIds.getString(EntitlementTableColumns.POLICY_ID));
                } while (policyIds.next());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to access an entitlement policy which does not exist");
                }
                return null;
            }

            return policies.toArray(new String[0]);

        } catch (SQLException e) {
            log.error("Error while retrieving all entitlement policy identifiers from PAP policy store", e);
            throw new EntitlementException(
                    "Error while retrieving entitlement policy " + "identifiers from PAP policy store");
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policyIds, getPolicyIdsPrepStmt);
        }
    }


    /**
     * Returns given policy as a PolicyDTO
     *
     * @param policyId policy id
     * @return policy as a PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    @Override
    public PolicyDTO getPolicy(String policyId) throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving entitlement policy");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyPrepStmt = null;
        ResultSet policy = null;

        try {
            getPolicyPrepStmt = connection.prepareStatement(GET_PAP_POLICY_SQL);
            getPolicyPrepStmt.setInt(1, 1);
            getPolicyPrepStmt.setInt(2, tenantId);
            getPolicyPrepStmt.setString(3, policyId);
            getPolicyPrepStmt.setString(4, policyId);
            getPolicyPrepStmt.setInt(5, tenantId);
            policy = getPolicyPrepStmt.executeQuery();

            if (policy.next()) {
                PolicyDTO dto = new PolicyDTO();

                dto.setPolicyId(policy.getString(EntitlementTableColumns.POLICY_ID));

                String version = String.valueOf(policy.getInt(EntitlementTableColumns.VERSION));
                dto.setVersion(version);

                String lastModifiedTime = policy.getString(EntitlementTableColumns.LAST_MODIFIED_TIME);
                if (lastModifiedTime != null) {
                    dto.setLastModifiedTime(lastModifiedTime);
                }

                String lastModifiedUser = policy.getString(EntitlementTableColumns.LAST_MODIFIED_USER);
                if (lastModifiedUser != null) {
                    dto.setLastModifiedUser(lastModifiedUser);
                }

                int isActiveInt = policy.getInt(EntitlementTableColumns.IS_ACTIVE);
                dto.setActive((isActiveInt != 0));

                int policyOrder = policy.getInt(EntitlementTableColumns.POLICY_ORDER);
                dto.setPolicyOrder(policyOrder);

                dto.setPolicyType(policy.getString(EntitlementTableColumns.POLICY_TYPE));

                dto.setPolicyEditor(policy.getString(EntitlementTableColumns.POLICY_EDITOR));

                dto.setPolicy(policy.getString(EntitlementTableColumns.POLICY));

                //Get policy references
                List<String> policyReferences = new ArrayList<>();
                PreparedStatement getPolicyRefsPrepStmt = connection.prepareStatement(GET_PAP_POLICY_REFS_SQL);
                getPolicyRefsPrepStmt.setInt(1, tenantId);
                getPolicyRefsPrepStmt.setString(2, policyId);
                getPolicyRefsPrepStmt.setInt(3, policy.getInt(EntitlementTableColumns.VERSION));
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
                getPolicySetRefsPrepStmt.setString(2, policyId);
                getPolicySetRefsPrepStmt.setInt(3, policy.getInt(EntitlementTableColumns.VERSION));
                ResultSet policySetRefs = getPolicySetRefsPrepStmt.executeQuery();

                if (policySetRefs.next()) {
                    do {
                        policySetReferences.add(policySetRefs.getString(EntitlementTableColumns.SET_REFERENCE));
                    } while (policySetRefs.next());
                }
                dto.setPolicySetIdReferences(policySetReferences.toArray(new String[0]));
                IdentityDatabaseUtil.closeResultSet(policySetRefs);
                IdentityDatabaseUtil.closeStatement(getPolicySetRefsPrepStmt);

                //Get policy editor data
                PreparedStatement getPolicyEditorDataPrepStmt =
                        connection.prepareStatement(GET_PAP_POLICY_EDITOR_DATA_SQL, ResultSet.TYPE_SCROLL_INSENSITIVE,
                                ResultSet.CONCUR_READ_ONLY);
                getPolicyEditorDataPrepStmt.setString(1, policyId);
                getPolicyEditorDataPrepStmt.setInt(2, Integer.parseInt(version));
                getPolicyEditorDataPrepStmt.setInt(3, tenantId);
                ResultSet EditorMetadata = getPolicyEditorDataPrepStmt.executeQuery();

                int rowCount = 0;
                if (EditorMetadata != null) {
                    EditorMetadata.last();
                    rowCount = EditorMetadata.getRow();
                    EditorMetadata.beforeFirst();
                }

                String[] basicPolicyEditorMetaData = new String[rowCount];
                for (int i = 0; i < rowCount; i++) {
                    EditorMetadata.beforeFirst();
                    while (EditorMetadata.next()) {
                        if (Objects.equals(EditorMetadata.getString(EntitlementTableColumns.EDITOR_DATA_NAME),
                                PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i)) {
                            basicPolicyEditorMetaData[i] =
                                    EditorMetadata.getString(EntitlementTableColumns.EDITOR_DATA);
                            break;
                        }
                    }
                }
                dto.setPolicyEditorData(basicPolicyEditorMetaData);

                IdentityDatabaseUtil.closeResultSet(EditorMetadata);
                IdentityDatabaseUtil.closeStatement(getPolicyEditorDataPrepStmt);

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt =
                        connection.prepareStatement(GET_PAP_POLICY_META_DATA_SQL, ResultSet.TYPE_SCROLL_INSENSITIVE,
                                ResultSet.CONCUR_READ_ONLY);
                getPolicyMetaDataPrepStmt.setString(1, policyId);
                getPolicyMetaDataPrepStmt.setInt(2, Integer.parseInt(version));
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

                return dto;

            } else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy " + policyId + " from the PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " +
                    policyId + " from the PAP policy store");
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policy, getPolicyPrepStmt);
        }
    }


    /**
     * Returns given policy version as a PolicyDTO
     *
     * @param policyId policy id
     * @param version  version
     * @return policy as a PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    @Override
    public PolicyDTO getPolicy(String policyId, String version) throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving entitlement policy for the given version");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyPrepStmt = null;
        ResultSet policy = null;

        try {
            getPolicyPrepStmt = connection.prepareStatement(GET_PAP_POLICY_BY_VERSION_SQL);
            getPolicyPrepStmt.setInt(1, 1);
            getPolicyPrepStmt.setInt(2, tenantId);
            getPolicyPrepStmt.setString(3, policyId);
            getPolicyPrepStmt.setInt(4, Integer.parseInt(version));
            policy = getPolicyPrepStmt.executeQuery();

            if (policy.next()) {
                PolicyDTO dto = new PolicyDTO();

                dto.setPolicyId(policyId);
                dto.setVersion(version);

                String lastModifiedTime = policy.getString(EntitlementTableColumns.LAST_MODIFIED_TIME);
                if (lastModifiedTime != null) {
                    dto.setLastModifiedTime(lastModifiedTime);
                }

                String lastModifiedUser = policy.getString(EntitlementTableColumns.LAST_MODIFIED_USER);
                if (lastModifiedUser != null) {
                    dto.setLastModifiedUser(lastModifiedUser);
                }

                int isActiveInt = policy.getInt(EntitlementTableColumns.IS_ACTIVE);
                dto.setActive((isActiveInt != 0));

                int policyOrder = policy.getInt(EntitlementTableColumns.POLICY_ORDER);
                dto.setPolicyOrder(policyOrder);

                dto.setPolicyType(policy.getString(EntitlementTableColumns.POLICY_TYPE));

                dto.setPolicyEditor(policy.getString(EntitlementTableColumns.POLICY_EDITOR));

                dto.setPolicy(policy.getString(EntitlementTableColumns.POLICY));

                //Get policy references
                List<String> policyReferences = new ArrayList<>();
                PreparedStatement getPolicyRefsPrepStmt = connection.prepareStatement(GET_PAP_POLICY_REFS_SQL);
                getPolicyRefsPrepStmt.setInt(1, tenantId);
                getPolicyRefsPrepStmt.setString(2, policyId);
                getPolicyRefsPrepStmt.setInt(3, Integer.parseInt(version));
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
                getPolicySetRefsPrepStmt.setString(2, policyId);
                getPolicySetRefsPrepStmt.setInt(3, Integer.parseInt(version));
                ResultSet policySetRefs = getPolicySetRefsPrepStmt.executeQuery();

                if (policySetRefs.next()) {
                    do {
                        policySetReferences.add(policySetRefs.getString(EntitlementTableColumns.SET_REFERENCE));
                    } while (policySetRefs.next());
                }
                dto.setPolicySetIdReferences(policySetReferences.toArray(new String[0]));
                IdentityDatabaseUtil.closeResultSet(policySetRefs);
                IdentityDatabaseUtil.closeStatement(getPolicySetRefsPrepStmt);

                //Get policy editor data
                PreparedStatement getPolicyEditorDataPrepStmt =
                        connection.prepareStatement(GET_PAP_POLICY_EDITOR_DATA_SQL, ResultSet.TYPE_SCROLL_INSENSITIVE,
                                ResultSet.CONCUR_READ_ONLY);
                getPolicyEditorDataPrepStmt.setString(1, policyId);
                getPolicyEditorDataPrepStmt.setInt(2, Integer.parseInt(version));
                getPolicyEditorDataPrepStmt.setInt(3, tenantId);
                ResultSet EditorMetadata = getPolicyEditorDataPrepStmt.executeQuery();

                int rowCount = 0;
                if (EditorMetadata != null) {
                    EditorMetadata.last();
                    rowCount = EditorMetadata.getRow();
                    EditorMetadata.beforeFirst();
                }

                String[] basicPolicyEditorMetaData = new String[rowCount];
                for (int i = 0; i < rowCount; i++) {
                    EditorMetadata.beforeFirst();
                    while (EditorMetadata.next()) {
                        if (Objects.equals(EditorMetadata.getString(EntitlementTableColumns.EDITOR_DATA_NAME),
                                PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i)) {
                            basicPolicyEditorMetaData[i] =
                                    EditorMetadata.getString(EntitlementTableColumns.EDITOR_DATA);
                            break;
                        }
                    }
                }
                dto.setPolicyEditorData(basicPolicyEditorMetaData);

                IdentityDatabaseUtil.closeResultSet(EditorMetadata);
                IdentityDatabaseUtil.closeStatement(getPolicyEditorDataPrepStmt);

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt =
                        connection.prepareStatement(GET_PAP_POLICY_META_DATA_SQL, ResultSet.TYPE_SCROLL_INSENSITIVE,
                                ResultSet.CONCUR_READ_ONLY);
                getPolicyMetaDataPrepStmt.setString(1, policyId);
                getPolicyMetaDataPrepStmt.setInt(2, Integer.parseInt(version));
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

                return dto;

            } else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy " + policyId + " from the PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " +
                    policyId + " from the PAP policy store");
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policy, getPolicyPrepStmt);
        }
    }


    /**
     * Returns all policies as a PolicyDTO array
     *
     * @return policies as a PolicyDTO array
     * @throws EntitlementException throws if fails
     */
    @Override
    public PolicyDTO[] getAllPolicies() throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        ResultSet policies = null;
        PreparedStatement getAllPoliciesPrepStmt = null;
        List<PolicyDTO> policyDTOList = new ArrayList<>();

        try {
            //Get all policies with latest version
            getAllPoliciesPrepStmt = connection.prepareStatement(GET_ALL_PAP_POLICIES_SQL);
            getAllPoliciesPrepStmt.setInt(1, 1);
            getAllPoliciesPrepStmt.setInt(2, tenantId);
            getAllPoliciesPrepStmt.setInt(3, tenantId);
            policies = getAllPoliciesPrepStmt.executeQuery();

            if (policies.next()) {
                do {
                    PolicyDTO dto = new PolicyDTO();

                    dto.setPolicyId(policies.getString(EntitlementTableColumns.POLICY_ID));

                    String version = String.valueOf(policies.getInt(EntitlementTableColumns.VERSION));
                    dto.setVersion(version);

                    String lastModifiedTime = policies.getString(EntitlementTableColumns.LAST_MODIFIED_TIME);
                    if (lastModifiedTime != null) {
                        dto.setLastModifiedTime(lastModifiedTime);
                    }

                    String lastModifiedUser = policies.getString(EntitlementTableColumns.LAST_MODIFIED_USER);
                    if (lastModifiedUser != null) {
                        dto.setLastModifiedUser(lastModifiedUser);
                    }

                    int isActiveInt = policies.getInt(EntitlementTableColumns.IS_ACTIVE);
                    dto.setActive((isActiveInt != 0));

                    int policyOrder = policies.getInt(EntitlementTableColumns.POLICY_ORDER);
                    dto.setPolicyOrder(policyOrder);

                    dto.setPolicyType(policies.getString(EntitlementTableColumns.POLICY_TYPE));

                    dto.setPolicyEditor(policies.getString(EntitlementTableColumns.POLICY_EDITOR));

                    //Get policy references
                    List<String> policyReferences = new ArrayList<>();
                    PreparedStatement getPolicyRefsPrepStmt = connection.prepareStatement(GET_PAP_POLICY_REFS_SQL);
                    getPolicyRefsPrepStmt.setInt(1, tenantId);
                    getPolicyRefsPrepStmt.setString(2,
                            policies.getString(EntitlementTableColumns.POLICY_ID));
                    getPolicyRefsPrepStmt.setInt(3, Integer.parseInt(version));
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
                    PreparedStatement getPolicySetRefsPrepStmt =
                            connection.prepareStatement(GET_PAP_POLICY_SET_REFS_SQL);
                    getPolicySetRefsPrepStmt.setInt(1, tenantId);
                    getPolicySetRefsPrepStmt.setString(2,
                            policies.getString(EntitlementTableColumns.POLICY_ID));
                    getPolicySetRefsPrepStmt.setInt(3, Integer.parseInt(version));
                    ResultSet policySetRefs = getPolicySetRefsPrepStmt.executeQuery();

                    if (policySetRefs.next()) {
                        do {
                            policySetReferences.add(policySetRefs.getString(EntitlementTableColumns.SET_REFERENCE));
                        } while (policySetRefs.next());
                    }
                    dto.setPolicySetIdReferences(policySetReferences.toArray(new String[0]));
                    IdentityDatabaseUtil.closeResultSet(policySetRefs);
                    IdentityDatabaseUtil.closeStatement(getPolicySetRefsPrepStmt);

                    policyDTOList.add(dto);

                } while (policies.next());

                return policyDTOList.toArray(new PolicyDTO[0]);

            } else {
                return new PolicyDTO[0];
            }

        } catch (SQLException e) {
            log.error("Error while retrieving all entitlement policies from PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policies from PAP policy store");
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policies, getAllPoliciesPrepStmt);
        }
    }


    /**
     * Adds or updates the given policy
     *
     * @param policy policy DTO
     * @param toPAP  whether the policy is in PAP or not
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void addOrUpdatePolicy(PolicyDTO policy, Boolean toPAP) throws EntitlementException {

        boolean newPolicy = false;
        OMElement omElement = null;
        String policyId = policy.getPolicyId();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        if (log.isDebugEnabled()) {
            log.debug("Creating or updating entitlement policy");
        }

        if (policyId == null) {
            log.error("Error while creating or updating entitlement policy: " +
                    "Policy DTO or Policy Id can not be null");
            throw new EntitlementException("Invalid Entitlement Policy. Policy or policyId can not be Null");
        }

        try {

            //Find policy meta data
            Properties properties = null;
            if (StringUtils.isNotBlank(policy.getPolicy())) {
                newPolicy = true;
                PolicyAttributeBuilder policyAttributeBuilder = new PolicyAttributeBuilder(policy.getPolicy());
                properties = policyAttributeBuilder.getPolicyMetaDataFromPolicy();
            }

            //Find policy type
            String policyType = null;
            if (policy.getPolicyType() != null && !policy.getPolicyType().trim().isEmpty()) {
                policyType = policy.getPolicyType();
                try {
                    omElement = AXIOMUtil.stringToOM(policy.getPolicy());
                } catch (XMLStreamException e) {
                    log.warn("Failed converting the policy into the OMElement");
                }
            } else {
                try {
                    if (newPolicy) {
                        omElement = AXIOMUtil.stringToOM(policy.getPolicy());
                        policyType = omElement.getLocalName();
                    }
                } catch (XMLStreamException e) {
                    policyType = PDPConstants.POLICY_ELEMENT;
                    log.warn("Policy Type can not be found. Default type is set");
                }
            }

            //Find policy editor type
            String policyEditorType = null;
            if (policy.getPolicyEditor() != null && !policy.getPolicyEditor().trim().isEmpty()) {
                policyEditorType = policy.getPolicyEditor().trim();
            }

            //Write a new policy
            int active = policy.isActive() ? 1 : 0;
            int promote = policy.isPromote() ? 1 : 0;
            PreparedStatement createPolicyPrepStmt = connection.prepareStatement(CREATE_PAP_POLICY_SQL);

            createPolicyPrepStmt.setString(1, policyId);
            createPolicyPrepStmt.setInt(2, Integer.parseInt(policy.getVersion()));
            createPolicyPrepStmt.setInt(3, tenantId);
            createPolicyPrepStmt.setInt(4, promote);
            createPolicyPrepStmt.setString(5, policy.getPolicy());
            createPolicyPrepStmt.setInt(6, active);
            createPolicyPrepStmt.setString(7, policyType);
            createPolicyPrepStmt.setString(8, policyEditorType);
            createPolicyPrepStmt.setInt(9, 0);
            createPolicyPrepStmt.setString(10, Long.toString(System.currentTimeMillis()));
            createPolicyPrepStmt.setString(11, CarbonContext.getThreadLocalCarbonContext().getUsername());

            createPolicyPrepStmt.executeUpdate();
            IdentityDatabaseUtil.closeStatement(createPolicyPrepStmt);

            //Write policy references and policy set references of the policy
            if (omElement != null) {
                Iterator iterator1 = omElement.getChildrenWithLocalName(PDPConstants.POLICY_ID_REFERENCE);
                if (iterator1 != null) {
                    PreparedStatement createPolicyReferencesPrepStmt =
                            connection.prepareStatement(CREATE_PAP_POLICY_REFS_SQL);
                    while (iterator1.hasNext()) {
                        OMElement policyReference = (OMElement) iterator1.next();

                        createPolicyReferencesPrepStmt.setString(1, policyReference.getText());
                        createPolicyReferencesPrepStmt.setString(2, policyId);
                        createPolicyReferencesPrepStmt.setInt(3, Integer.parseInt(policy.getVersion()));
                        createPolicyReferencesPrepStmt.setInt(4, tenantId);
                        createPolicyReferencesPrepStmt.addBatch();
                    }
                    createPolicyReferencesPrepStmt.executeBatch();
                    IdentityDatabaseUtil.closeStatement(createPolicyReferencesPrepStmt);
                }
                Iterator iterator2 = omElement.getChildrenWithLocalName(PDPConstants.POLICY_SET_ID_REFERENCE);
                if (iterator2 != null) {
                    PreparedStatement createPolicySetReferencesPrepStmt =
                            connection.prepareStatement(CREATE_PAP_POLICY_SET_REFS_SQL);
                    while (iterator2.hasNext()) {
                        OMElement policySetReference = (OMElement) iterator2.next();

                        createPolicySetReferencesPrepStmt.setString(1, policySetReference.getText());
                        createPolicySetReferencesPrepStmt.setString(2, policyId);
                        createPolicySetReferencesPrepStmt.setInt(3, Integer.parseInt(policy.getVersion()));
                        createPolicySetReferencesPrepStmt.setInt(4, tenantId);
                        createPolicySetReferencesPrepStmt.addBatch();
                    }
                    createPolicySetReferencesPrepStmt.executeBatch();
                    IdentityDatabaseUtil.closeStatement(createPolicySetReferencesPrepStmt);
                }
            }

            //Write attributes of the policy
            if (properties != null) {
                PreparedStatement createAttributesPrepStmt =
                        connection.prepareStatement(CREATE_PAP_POLICY_ATTRIBUTES_SQL);

                for (Object o : properties.keySet()) {
                    String key = o.toString();

                    createAttributesPrepStmt.setString(1, key);
                    createAttributesPrepStmt.setString(2,
                            Collections.singletonList(properties.get(key)).toString());
                    createAttributesPrepStmt.setString(3, policyId);
                    createAttributesPrepStmt.setInt(4, Integer.parseInt(policy.getVersion()));
                    createAttributesPrepStmt.setInt(5, tenantId);
                    createAttributesPrepStmt.addBatch();
                }
                createAttributesPrepStmt.executeBatch();
                IdentityDatabaseUtil.closeStatement(createAttributesPrepStmt);
            }

            //Write policy editor data
            String[] policyMetaData = policy.getPolicyEditorData();
            if (policyMetaData != null && policyMetaData.length > 0) {
                PreparedStatement createPolicyEditorDataPrepStmt =
                        connection.prepareStatement(CREATE_PAP_POLICY_EDITOR_DATA_SQL);
                int i = 0;
                for (String policyData : policyMetaData) {
                    if (policyData != null && !policyData.isEmpty()) {

                        createPolicyEditorDataPrepStmt.setString(1,
                                (PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i));
                        createPolicyEditorDataPrepStmt.setString(2, policyData);
                        createPolicyEditorDataPrepStmt.setString(3, policyId);
                        createPolicyEditorDataPrepStmt.setInt(4, Integer.parseInt(policy.getVersion()));
                        createPolicyEditorDataPrepStmt.setInt(5, tenantId);
                    }
                    createPolicyEditorDataPrepStmt.addBatch();
                    i++;
                }
                createPolicyEditorDataPrepStmt.executeBatch();
                IdentityDatabaseUtil.closeStatement(createPolicyEditorDataPrepStmt);
            }

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new EntitlementException("Error while adding or updating entitlement policy in policy store");
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    /**
     * Removes the given policy from the policy store
     *
     * @param policyId policyId
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void removePolicy(String policyId) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (log.isDebugEnabled()) {
            log.debug("Removing entitlement policy");
        }
        try {

            //Find whether the policy is published or not
            PreparedStatement findPDPPresencePrepStmt = connection.prepareStatement(GET_POLICY_PDP_PRESENCE_SQL);
            findPDPPresencePrepStmt.setString(1, policyId);
            findPDPPresencePrepStmt.setInt(2, 1);
            findPDPPresencePrepStmt.setInt(3, tenantId);
            ResultSet rs1 = findPDPPresencePrepStmt.executeQuery();

            if (rs1.next()) {

                //Remove the unpublished versions of the policy from the database
                PreparedStatement removePolicyByIdAndVersionPrepStmt =
                        connection.prepareStatement(DELETE_UNPUBLISHED_POLICY_VERSIONS_SQL);
                removePolicyByIdAndVersionPrepStmt.setString(1, policyId);
                removePolicyByIdAndVersionPrepStmt.setInt(2, tenantId);
                removePolicyByIdAndVersionPrepStmt.setInt(3, 0);
                removePolicyByIdAndVersionPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyByIdAndVersionPrepStmt);

                //Remove the published version of the policy from the PAP (It is still present in PDP)
                PreparedStatement removePolicyFromPAPPrepStmt = connection.prepareStatement(DELETE_PAP_POLICY_SQL);
                removePolicyFromPAPPrepStmt.setInt(1, 0);
                removePolicyFromPAPPrepStmt.setString(2, policyId);
                removePolicyFromPAPPrepStmt.setInt(3, 1);
                removePolicyFromPAPPrepStmt.setInt(4, tenantId);
                removePolicyFromPAPPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyFromPAPPrepStmt);

            } else {
                //Remove the policy from the database
                PreparedStatement removePolicyPrepStmt = connection.prepareStatement(DELETE_POLICY_SQL);
                removePolicyPrepStmt.setString(1, policyId);
                removePolicyPrepStmt.setInt(2, tenantId);
                removePolicyPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyPrepStmt);
            }

            IdentityDatabaseUtil.closeResultSet(rs1);
            IdentityDatabaseUtil.closeStatement(findPDPPresencePrepStmt);
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("Error while removing entitlement policy " + policyId + " from PAP policy store", e);
            throw new EntitlementException("Error while removing policy " + policyId + " from PAP policy store");
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    /**
     * Removes the given policy version from the policy store
     *
     * @param policyId policyId
     * @param version  version
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void removePolicy(String policyId, int version) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (log.isDebugEnabled()) {
            log.debug("Removing entitlement policy version");
        }
        try {

            //Find whether the policy is published or not
            PreparedStatement findPDPPresencePrepStmt =
                    connection.prepareStatement(GET_POLICY_PDP_PRESENCE_BY_VERSION_SQL);
            findPDPPresencePrepStmt.setString(1, policyId);
            findPDPPresencePrepStmt.setInt(2, 1);
            findPDPPresencePrepStmt.setInt(3, tenantId);
            findPDPPresencePrepStmt.setInt(4, version);
            ResultSet rs1 = findPDPPresencePrepStmt.executeQuery();

            if (rs1.next()) {

                //Remove the policy version from the PAP (It is still present in PDP)
                PreparedStatement removePolicyFromPAPPrepStmt =
                        connection.prepareStatement(DELETE_PAP_POLICY_BY_VERSION_SQL);
                removePolicyFromPAPPrepStmt.setInt(1, 0);
                removePolicyFromPAPPrepStmt.setString(2, policyId);
                removePolicyFromPAPPrepStmt.setInt(3, version);
                removePolicyFromPAPPrepStmt.setInt(4, tenantId);
                removePolicyFromPAPPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyFromPAPPrepStmt);

            } else {
                //Remove the policy version from the database
                PreparedStatement removePolicyPrepStmt = connection.prepareStatement(DELETE_POLICY_VERSION_SQL);
                removePolicyPrepStmt.setString(1, policyId);

                removePolicyPrepStmt.setInt(2, tenantId);
                removePolicyPrepStmt.setInt(3, version);
                removePolicyPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyPrepStmt);
            }

            IdentityDatabaseUtil.closeResultSet(rs1);
            IdentityDatabaseUtil.closeStatement(findPDPPresencePrepStmt);
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("Error while removing entitlement policy version " + policyId + " " + version +
                    " from PAP policy store", e);
            throw new EntitlementException("Error while removing policy version " + policyId + " " + version +
                    " from PAP policy store");
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

}
