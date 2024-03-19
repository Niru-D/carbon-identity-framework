/*
 *  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.entitlement.pap.store;

import com.sun.media.sound.MidiDeviceReceiverEnvelope;
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
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.identity.entitlement.policy.PolicyAttributeBuilder;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

import javax.xml.stream.XMLStreamException;
import java.sql.*;
import java.util.*;


public class PAPPolicyStore {

    // The logger we'll use for all messages
    private static final Log log = LogFactory.getLog(PAPPolicyStore.class);
    private Registry registry;
    private DataSource dataSource;

    public PAPPolicyStore() {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        registry = EntitlementServiceComponent.getGovernanceRegistry(tenantId);
    }

    public PAPPolicyStore(Registry registry) throws EntitlementException {
        if (registry == null) {
            log.error("Registry reference not set");
            throw new EntitlementException("Registry reference not set");
        }
        this.registry = registry;
    }


    /**
     * This returns all the policy ids as String list. Here we assume registry resource name as
     * the policy id.
     *
     * @return policy ids as String[]
     * @throws EntitlementException throws if fails
     */
    public String[] getAllPolicyIds() throws EntitlementException {
//        String path = null;
//        Collection collection = null;
//        List<String> resources = new ArrayList<String>();
//        String[] children = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policy IDs");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        List<String> policies = new ArrayList<String>();
        PreparedStatement getPolicyIdsPrepStmt = null;
        ResultSet policyIds = null;

        try {
//            path = PDPConstants.ENTITLEMENT_POLICY_PAP;

//            if (!registry.resourceExists(path)) {
//                if (log.isDebugEnabled()) {
//                    log.debug("Trying to access an entitlement policy which does not exist");
//                }
//                return null;
//            }
//            collection = (Collection) registry.get(path);
//            children = collection.getChildren();
//            for (String child : children) {
//                String[] resourcePath = child.split("/");
//                if (resourcePath != null && resourcePath.length > 0) {
//                    resources.add(resourcePath[resourcePath.length - 1]);
//                }
//            }
            getPolicyIdsPrepStmt = connection.prepareStatement(
                    "SELECT DISTINCT POLICY_ID FROM IDN_XACML_POLICY WHERE TENANT_ID=? AND IS_IN_PAP=?");
            getPolicyIdsPrepStmt.setInt(1, tenantId);
            getPolicyIdsPrepStmt.setInt(2, 1);
            policyIds = getPolicyIdsPrepStmt.executeQuery();

            if(policyIds.next()){
                do{
                    policies.add(policyIds.getString("POLICY_ID"));
                }while(policyIds.next());
            }else{
                if (log.isDebugEnabled()) {
                    log.debug("Trying to access an entitlement policy which does not exist");
                }
                return null;
            }

            return policies.toArray(new String[policies.size()]);

        } catch (SQLException e) {
            log.error("Error while retrieving all entitlement policy identifiers from PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " +
                                           "identifiers from PAP policy store");
        }finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policyIds, getPolicyIdsPrepStmt);
        }
    }


    /**
     * This returns given policy as a PolicyDTO
     *
     * @param policyId   policy id
     * @return policy as a PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    public Resource getPolicy(String policyId, String collection) throws EntitlementException {
        String path = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving entitlement policy");
        }

        try {
            path = collection + policyId;

            if (!registry.resourceExists(path)) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to access an entitlement policy which does not exist");
                }
                return null;
            }
            return registry.get(path);
        } catch (RegistryException e) {
            log.error("Error while retrieving entitlement policy " + policyId + " PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " + policyId
                                           + " PAP policy store");
        }
    }

    public PolicyDTO getPolicy(String policyId) throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving entitlement policy");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyPrepStmt = null;
        ResultSet policy = null;

        try {
            getPolicyPrepStmt = connection.prepareStatement(
                    "SELECT t1.*, " +
                            "GROUP_CONCAT(DISTINCT ref.reference ORDER BY ref.reference ASC SEPARATOR ',') " +
                            "AS POLICY_REFERENCES, " +
                            "GROUP_CONCAT(DISTINCT set_ref.set_reference ORDER BY set_ref.set_reference " +
                            "ASC SEPARATOR ', ') AS POLICY_SET_REFERENCES " +
                            "FROM IDN_XACML_POLICY t1 LEFT JOIN idn_xacml_policy_reference ref ON " +
                            "t1.POLICY_ID = ref.POLICY_ID AND t1.VERSION = ref.VERSION AND t1.TENANT_ID = ref.TENANT_ID " +
                            "LEFT JOIN idn_xacml_policy_set_reference set_ref ON " +
                            "t1.POLICY_ID = set_ref.POLICY_ID AND t1.VERSION = set_ref.VERSION AND " +
                            "t1.TENANT_ID = set_ref.TENANT_ID " +
                            "WHERE t1.IS_IN_PAP = ? AND t1.TENANT_ID = ? AND t1.POLICY_ID = ? AND " +
                            "t1.version = (SELECT MAX(VERSION) FROM IDN_XACML_POLICY t2 " +
                            "WHERE t2.POLICY_ID = t1.POLICY_ID) GROUP BY t1.POLICY_ID, t1.VERSION, t1.TENANT_ID");
            getPolicyPrepStmt.setInt(1,1);
            getPolicyPrepStmt.setInt(2, tenantId);
            getPolicyPrepStmt.setString(3, policyId);
            policy = getPolicyPrepStmt.executeQuery();

            if(policy.next()){
                PolicyDTO dto = new PolicyDTO();

                dto.setPolicyId(policy.getString("POLICY_ID"));

                String version = String.valueOf(policy.getInt("VERSION"));
                if (version != null) {
                    dto.setVersion(version);
                }

                String lastModifiedTime = policy.getString("LAST_MODIFIED_TIME");
                if (lastModifiedTime != null) {
                    dto.setLastModifiedTime(lastModifiedTime);
                }

                String lastModifiedUser = policy.getString("LAST_MODIFIED_USER");
                if (lastModifiedUser != null) {
                    dto.setLastModifiedUser(lastModifiedUser);
                }

                int isActiveInt = policy.getInt("IS_ACTIVE");
                dto.setActive((isActiveInt != 0));

                int policyOrder = policy.getInt("POLICY_ORDER");
                dto.setPolicyOrder(policyOrder);

                dto.setPolicyType(policy.getString("POLICY_TYPE"));

                String policyReferences = policy.getString("POLICY_REFERENCES");
                if (policyReferences != null && !policyReferences.trim().isEmpty()) {
                    dto.setPolicyIdReferences(policyReferences.split(PDPConstants.ATTRIBUTE_SEPARATOR));
                }

                String policySetReferences = policy.getString("POLICY_SET_REFERENCES");
                if (policySetReferences != null && !policySetReferences.trim().isEmpty()) {
                    dto.setPolicySetIdReferences(policySetReferences.split(PDPConstants.ATTRIBUTE_SEPARATOR));
                }

                dto.setPolicyEditor(policy.getString("POLICY_EDITOR"));

                dto.setPolicy(policy.getString("POLICY"));

                //Get policy editor metadata
                PreparedStatement getPolicyEditorDataPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_EDITOR_DATA WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?",
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
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
                        if (Objects.equals(EditorMetadata.getString("NAME"),
                                PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i)) {
                            basicPolicyEditorMetaData[i] = EditorMetadata.getString("DATA");
                            break;
                        }
                    }
                }
                dto.setPolicyEditorData(basicPolicyEditorMetaData);

                IdentityDatabaseUtil.closeResultSet(EditorMetadata);
                IdentityDatabaseUtil.closeStatement(getPolicyEditorDataPrepStmt);

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_ATTRIBUTE WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?",
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
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
                        if (Objects.equals(metadata.getString("NAME"),
                                PDPConstants.POLICY_META_DATA + i)) {
                            properties.setProperty(PDPConstants.POLICY_META_DATA + i,
                                    metadata.getString("VALUE"));
                            break;
                        }
                    }
                }

                PolicyAttributeBuilder policyAttributeBuilder = new PolicyAttributeBuilder();
                dto.setAttributeDTOs(policyAttributeBuilder.getPolicyMetaData(properties));

                IdentityDatabaseUtil.closeResultSet(metadata);
                IdentityDatabaseUtil.closeStatement(getPolicyMetaDataPrepStmt);

                return dto;

            }else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy " + policyId + " from the PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " + policyId
                    + " from the PAP policy store");
        }finally{
            IdentityDatabaseUtil.closeAllConnections(connection, policy, getPolicyPrepStmt);
        }
    }


    /**
     * This returns the requested policy version
     *
     * @param policyId   policy id
     * @param version   version
     * @return policy as a PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    public PolicyDTO getPolicyByVersion(String policyId, String version) throws EntitlementException{

        if (log.isDebugEnabled()) {
            log.debug("Retrieving entitlement policy for the given version");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyPrepStmt = null;
        ResultSet policy = null;

        try {
            getPolicyPrepStmt = connection.prepareStatement(
                    "SELECT t1.*, " +
                            "GROUP_CONCAT(DISTINCT ref.reference ORDER BY ref.reference ASC SEPARATOR ',') " +
                            "AS POLICY_REFERENCES, " +
                            "GROUP_CONCAT(DISTINCT set_ref.set_reference ORDER BY set_ref.set_reference " +
                            "ASC SEPARATOR ', ') AS POLICY_SET_REFERENCES " +
                            "FROM IDN_XACML_POLICY t1 LEFT JOIN idn_xacml_policy_reference ref ON " +
                            "t1.POLICY_ID = ref.POLICY_ID AND t1.VERSION = ref.VERSION AND t1.TENANT_ID = ref.TENANT_ID " +
                            "LEFT JOIN idn_xacml_policy_set_reference set_ref ON " +
                            "t1.POLICY_ID = set_ref.POLICY_ID AND t1.VERSION = set_ref.VERSION AND " +
                            "t1.TENANT_ID = set_ref.TENANT_ID " +
                            "WHERE t1.IS_IN_PAP = ? AND t1.TENANT_ID = ? AND t1.POLICY_ID = ? AND " +
                            "t1.version = ?");
            getPolicyPrepStmt.setInt(1,1);
            getPolicyPrepStmt.setInt(2, tenantId);
            getPolicyPrepStmt.setString(3, policyId);
            getPolicyPrepStmt.setInt(4, Integer.parseInt(version));
            policy = getPolicyPrepStmt.executeQuery();

            if(policy.next()){
                PolicyDTO dto = new PolicyDTO();

                dto.setPolicyId(policyId);
                dto.setVersion(version);

                String lastModifiedTime = policy.getString("LAST_MODIFIED_TIME");
                if (lastModifiedTime != null) {
                    dto.setLastModifiedTime(lastModifiedTime);
                }

                String lastModifiedUser = policy.getString("LAST_MODIFIED_USER");
                if (lastModifiedUser != null) {
                    dto.setLastModifiedUser(lastModifiedUser);
                }

                int isActiveInt = policy.getInt("IS_ACTIVE");
                dto.setActive((isActiveInt != 0));

                int policyOrder = policy.getInt("POLICY_ORDER");
                dto.setPolicyOrder(policyOrder);

                dto.setPolicyType(policy.getString("POLICY_TYPE"));

                String policyReferences = policy.getString("POLICY_REFERENCES");
                if (policyReferences != null && !policyReferences.trim().isEmpty()) {
                    dto.setPolicyIdReferences(policyReferences.split(PDPConstants.ATTRIBUTE_SEPARATOR));
                }

                String policySetReferences = policy.getString("POLICY_SET_REFERENCES");
                if (policySetReferences != null && !policySetReferences.trim().isEmpty()) {
                    dto.setPolicySetIdReferences(policySetReferences.split(PDPConstants.ATTRIBUTE_SEPARATOR));
                }

                dto.setPolicyEditor(policy.getString("POLICY_EDITOR"));

                dto.setPolicy(policy.getString("POLICY"));

                //Get policy editor metadata
                PreparedStatement getPolicyEditorDataPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_EDITOR_DATA WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?",
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
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
                        if (Objects.equals(EditorMetadata.getString("NAME"),
                                PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i)) {
                            basicPolicyEditorMetaData[i] = EditorMetadata.getString("DATA");
                            break;
                        }
                    }
                }
                dto.setPolicyEditorData(basicPolicyEditorMetaData);

                IdentityDatabaseUtil.closeResultSet(EditorMetadata);
                IdentityDatabaseUtil.closeStatement(getPolicyEditorDataPrepStmt);

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_ATTRIBUTE WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?",
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
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
                        if (Objects.equals(metadata.getString("NAME"),
                                PDPConstants.POLICY_META_DATA + i)) {
                            properties.setProperty(PDPConstants.POLICY_META_DATA + i,
                                    metadata.getString("VALUE"));
                            break;
                        }
                    }
                }

                PolicyAttributeBuilder policyAttributeBuilder = new PolicyAttributeBuilder();
                dto.setAttributeDTOs(policyAttributeBuilder.getPolicyMetaData(properties));

                IdentityDatabaseUtil.closeResultSet(metadata);
                IdentityDatabaseUtil.closeStatement(getPolicyMetaDataPrepStmt);

                return dto;

            }else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy " + policyId + " from the PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " + policyId
                    + " from the PAP policy store");
        }finally{
            IdentityDatabaseUtil.closeAllConnections(connection, policy, getPolicyPrepStmt);
        }
    }


    /**
     * This returns all policies as a PolicyDTO array
     *
     * @return policies as a PolicyDTO array
     * @throws EntitlementException throws if fails
     */
    public PolicyDTO[] getAllPolicies() throws EntitlementException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        ResultSet policies =null;
        PreparedStatement getAllPoliciesPrepStmt=null;
        List<PolicyDTO> policyDTOList = new ArrayList<PolicyDTO>();

        try {
            //Get all policies with latest version
            getAllPoliciesPrepStmt = connection.prepareStatement(
                    "SELECT t1.*, " +
                            "GROUP_CONCAT(DISTINCT ref.reference ORDER BY ref.reference ASC SEPARATOR ',') " +
                            "AS POLICY_REFERENCES, " +
                            "GROUP_CONCAT(DISTINCT set_ref.set_reference ORDER BY set_ref.set_reference " +
                            "ASC SEPARATOR ', ') AS POLICY_SET_REFERENCES " +
                            "FROM IDN_XACML_POLICY t1 LEFT JOIN idn_xacml_policy_reference ref ON " +
                            "t1.POLICY_ID = ref.POLICY_ID AND t1.VERSION = ref.VERSION AND t1.TENANT_ID = ref.TENANT_ID " +
                            "LEFT JOIN idn_xacml_policy_set_reference set_ref ON " +
                            "t1.POLICY_ID = set_ref.POLICY_ID AND t1.VERSION = set_ref.VERSION AND " +
                            "t1.TENANT_ID = set_ref.TENANT_ID " +
                            "WHERE t1.IS_IN_PAP = ? AND t1.TENANT_ID = ? AND " +
                            "t1.version = (SELECT MAX(VERSION) FROM IDN_XACML_POLICY t2 " +
                            "WHERE t2.POLICY_ID = t1.POLICY_ID) GROUP BY t1.POLICY_ID, t1.VERSION, t1.TENANT_ID");
            getAllPoliciesPrepStmt.setInt(1,1);
            getAllPoliciesPrepStmt.setInt(2, tenantId);
            policies = getAllPoliciesPrepStmt.executeQuery();

            if(policies.next()){
                do{
                    PolicyDTO dto = new PolicyDTO();

                    dto.setPolicyId(policies.getString("POLICY_ID"));

                    String version = String.valueOf(policies.getInt("VERSION"));
                    if (version != null) {
                        dto.setVersion(version);
                    }

                    String lastModifiedTime = policies.getString("LAST_MODIFIED_TIME");
                    if (lastModifiedTime != null) {
                        dto.setLastModifiedTime(lastModifiedTime);
                    }

                    String lastModifiedUser = policies.getString("LAST_MODIFIED_USER");
                    if (lastModifiedUser != null) {
                        dto.setLastModifiedUser(lastModifiedUser);
                    }

                    int isActiveInt = policies.getInt("IS_ACTIVE");
                    dto.setActive((isActiveInt != 0));

                    int policyOrder = policies.getInt("POLICY_ORDER");
                    dto.setPolicyOrder(policyOrder);

                    dto.setPolicyType(policies.getString("POLICY_TYPE"));

                    String policyReferences = policies.getString("POLICY_REFERENCES");
                    if (policyReferences != null && !policyReferences.trim().isEmpty()) {
                        dto.setPolicyIdReferences(policyReferences.split(PDPConstants.ATTRIBUTE_SEPARATOR));
                    }

                    String policySetReferences = policies.getString("POLICY_SET_REFERENCES");
                    if (policySetReferences != null && !policySetReferences.trim().isEmpty()) {
                        dto.setPolicySetIdReferences(policySetReferences.split(PDPConstants.ATTRIBUTE_SEPARATOR));
                    }

                    dto.setPolicyEditor(policies.getString("POLICY_EDITOR"));

                    policyDTOList.add(dto);

                }while (policies.next());

                return policyDTOList.toArray(new PolicyDTO[policyDTOList.size()]);

            }else {
                return new PolicyDTO[0];
            }

        } catch (SQLException e) {
            log.error("Error while retrieving all entitlement policies from PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policies from PAP policy store");
        }finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policies, getAllPoliciesPrepStmt);
        }
    }

    public void addOrUpdatePolicy(PolicyDTO policy, String policyPath) throws EntitlementException {
        addOrUpdatePolicy(policy, policy.getPolicyId(), policyPath);

    }

    public void addOrUpdatePolicyToNewRDBMS(PolicyDTO policy) throws EntitlementException {
        addOrUpdatePolicyToNewRDBMS(policy, policy.getPolicyId());

    }

    /**
     * @param policy
     * @throws EntitlementException
     */

    public void addOrUpdatePolicy(PolicyDTO policy, String policyId, String policyPath)
            throws EntitlementException {

        String path = null;
        Resource resource = null;
        boolean newPolicy = false;
        OMElement omElement = null;

        if (log.isDebugEnabled()) {
            log.debug("Creating or updating entitlement policy");
        }

        if (policy == null || policyId == null) {
            log.error("Error while creating or updating entitlement policy: " +
                      "Policy DTO or Policy Id can not be null");
            throw new EntitlementException("Invalid Entitlement Policy. Policy or policyId can not be Null");
        }

        try {
            path = policyPath + policyId;

            if (registry.resourceExists(path)) {
                resource = registry.get(path);
            } else {
                resource = registry.newResource();
            }

            Collection policyCollection;
            if (registry.resourceExists(policyPath)) {
                policyCollection = (Collection) registry.get(policyPath);
            } else {
                policyCollection = registry.newCollection();
            }

            if (policy.getPolicyOrder() > 0) {

                String noOfPolicies = policyCollection.getProperty(PDPConstants.MAX_POLICY_ORDER);
                if (noOfPolicies != null && Integer.parseInt(noOfPolicies) < policy.getPolicyOrder()) {
                    policyCollection.setProperty(PDPConstants.MAX_POLICY_ORDER,
                                                 Integer.toString(policy.getPolicyOrder()));
                    registry.put(policyPath, policyCollection);
                }
                resource.setProperty(PDPConstants.POLICY_ORDER,
                                     Integer.toString(policy.getPolicyOrder()));
            } else {
                String previousOrder = resource.getProperty(PDPConstants.POLICY_ORDER);
                if (previousOrder == null) {
                    if (policyCollection != null) {
                        int policyOrder = 1;
                        String noOfPolicies = policyCollection.getProperty(PDPConstants.MAX_POLICY_ORDER);
                        if (noOfPolicies != null) {
                            policyOrder = policyOrder + Integer.parseInt(noOfPolicies);
                        }
                        policyCollection.setProperty(PDPConstants.MAX_POLICY_ORDER,
                                                     Integer.toString(policyOrder));
                        resource.setProperty(PDPConstants.POLICY_ORDER, Integer.toString(policyOrder));
                    }
                    registry.put(policyPath, policyCollection);
                }
            }

            if (StringUtils.isNotBlank(policy.getPolicy())) {
                resource.setContent(policy.getPolicy());
                newPolicy = true;
                PolicyAttributeBuilder policyAttributeBuilder = new PolicyAttributeBuilder(policy.getPolicy());
                Properties properties = policyAttributeBuilder.getPolicyMetaDataFromPolicy();
                Properties resourceProperties = new Properties();
                for (Object o : properties.keySet()) {
                    String key = o.toString();
                    resourceProperties.put(key, Collections.singletonList(properties.get(key)));
                }
                resource.setProperties(resourceProperties);
            }

            resource.setProperty(PDPConstants.ACTIVE_POLICY, Boolean.toString(policy.isActive()));
            resource.setProperty(PDPConstants.PROMOTED_POLICY, Boolean.toString(policy.isPromote()));

            if (policy.getVersion() != null) {
                resource.setProperty(PDPConstants.POLICY_VERSION, policy.getVersion());
            }
            resource.setProperty(PDPConstants.LAST_MODIFIED_TIME, Long.toString(System.currentTimeMillis()));
            resource.setProperty(PDPConstants.LAST_MODIFIED_USER, CarbonContext.getThreadLocalCarbonContext()
                    .getUsername());

            if (policy.getPolicyType() != null && policy.getPolicyType().trim().length() > 0) {
                resource.setProperty(PDPConstants.POLICY_TYPE, policy.getPolicyType());
            } else {
                try {
                    if (newPolicy) {
                        omElement = AXIOMUtil.stringToOM(policy.getPolicy());
                        resource.setProperty(PDPConstants.POLICY_TYPE, omElement.getLocalName());
                    }
                } catch (XMLStreamException e) {
                    policy.setPolicyType(PDPConstants.POLICY_ELEMENT);
                    log.warn("Policy Type can not be found. Default type is set");
                }
            }

            if (omElement != null) {
                Iterator iterator1 = omElement.getChildrenWithLocalName(PDPConstants.
                                                                                POLICY_REFERENCE);
                if (iterator1 != null) {
                    String policyReferences = "";
                    while (iterator1.hasNext()) {
                        OMElement policyReference = (OMElement) iterator1.next();
                        if (!"".equals(policyReferences)) {
                            policyReferences = policyReferences + PDPConstants.ATTRIBUTE_SEPARATOR
                                               + policyReference.getText();
                        } else {
                            policyReferences = policyReference.getText();
                        }
                    }
                    resource.setProperty(PDPConstants.POLICY_REFERENCE, policyReferences);
                }

                Iterator iterator2 = omElement.getChildrenWithLocalName(PDPConstants.
                                                                                POLICY_SET_REFERENCE);
                if (iterator2 != null) {
                    String policySetReferences = "";
                    while (iterator1.hasNext()) {
                        OMElement policySetReference = (OMElement) iterator2.next();
                        if (!"".equals(policySetReferences)) {
                            policySetReferences = policySetReferences + PDPConstants.ATTRIBUTE_SEPARATOR
                                                  + policySetReference.getText();
                        } else {
                            policySetReferences = policySetReference.getText();
                        }
                    }
                    resource.setProperty(PDPConstants.POLICY_SET_REFERENCE, policySetReferences);
                }
            }

            //before writing basic policy editor meta data as properties,
            //delete any properties related to them
            String policyEditor = resource.getProperty(PDPConstants.POLICY_EDITOR_TYPE);
            if (newPolicy && policyEditor != null) {
                resource.removeProperty(PDPConstants.POLICY_EDITOR_TYPE);
            }

            //write policy meta data that is used for basic policy editor
            if (policy.getPolicyEditor() != null && policy.getPolicyEditor().trim().length() > 0) {
                resource.setProperty(PDPConstants.POLICY_EDITOR_TYPE, policy.getPolicyEditor().trim());
            }
            String[] policyMetaData = policy.getPolicyEditorData();
            if (policyMetaData != null && policyMetaData.length > 0) {
                String BasicPolicyEditorMetaDataAmount = resource.getProperty(PDPConstants.
                                                                                      BASIC_POLICY_EDITOR_META_DATA_AMOUNT);
                if (newPolicy && BasicPolicyEditorMetaDataAmount != null) {
                    int amount = Integer.parseInt(BasicPolicyEditorMetaDataAmount);
                    for (int i = 0; i < amount; i++) {
                        resource.removeProperty(PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i);
                    }
                    resource.removeProperty(PDPConstants.BASIC_POLICY_EDITOR_META_DATA_AMOUNT);
                }

                int i = 0;
                for (String policyData : policyMetaData) {
                    if (policyData != null && !"".equals(policyData)) {
                        resource.setProperty(PDPConstants.BASIC_POLICY_EDITOR_META_DATA + i,
                                             policyData);
                    }
                    i++;
                }
                resource.setProperty(PDPConstants.BASIC_POLICY_EDITOR_META_DATA_AMOUNT,
                                     Integer.toString(i));
            }

            registry.put(path, resource);

        } catch (RegistryException e) {
            log.error("Error while adding or updating entitlement policy " + policyId +
                      " in policy store", e);
            throw new EntitlementException("Error while adding or updating entitlement policy in policy store");
        }
    }

    /**
     * This adds the given policy to the policy store
     *
     * @param policy   policy DTO
     * @param policyId policyId
     * @throws EntitlementException throws, if fails
     */

    public void addOrUpdatePolicyToNewRDBMS(PolicyDTO policy, String policyId)
            throws EntitlementException {

        boolean newPolicy = false;
        OMElement omElement = null;
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        if (log.isDebugEnabled()) {
            log.debug("Creating or updating entitlement policy");
        }

        if (policy == null || policyId == null) {
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
                try{
                    omElement = AXIOMUtil.stringToOM(policy.getPolicy());
                }catch (XMLStreamException e) {
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
            int active = policy.isActive() ? 1: 0;
            int promote = policy.isPromote() ? 1: 0;
            PreparedStatement createPolicyPrepStmt = connection.prepareStatement(
                        "INSERT INTO IDN_XACML_POLICY (POLICY_ID, VERSION, TENANT_ID, IS_IN_PDP, IS_IN_PAP, " +
                                "POLICY, IS_ACTIVE, POLICY_TYPE, POLICY_EDITOR, POLICY_ORDER, LAST_MODIFIED_TIME, " +
                                "LAST_MODIFIED_USER) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)");

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
                    PreparedStatement createPolicyReferencesPrepStmt = connection.prepareStatement(
                            "INSERT INTO IDN_XACML_POLICY_REFERENCE (REFERENCE, POLICY_ID, VERSION, TENANT_ID) " +
                                    "VALUES (?, ?, ?, ?)");
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
                    PreparedStatement createPolicySetReferencesPrepStmt = connection.prepareStatement(
                            "INSERT INTO IDN_XACML_POLICY_SET_REFERENCE (SET_REFERENCE, POLICY_ID, VERSION, " +
                                    "TENANT_ID) VALUES (?, ?, ?, ?)");
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
            if(properties != null) {
                PreparedStatement createAttributesPrepStmt = connection.prepareStatement(
                        "INSERT INTO IDN_XACML_POLICY_ATTRIBUTE (NAME, VALUE, POLICY_ID, VERSION, TENANT_ID) " +
                                "VALUES (?, ?, ?, ?, ?)");

                for (Object o : properties.keySet()) {
                    String key = o.toString();

                    createAttributesPrepStmt.setString(1, key);
                    createAttributesPrepStmt.setString
                            (2, Collections.singletonList(properties.get(key)).toString());
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
            if(policyMetaData != null && policyMetaData.length > 0) {
                PreparedStatement createPolicyEditorDataPrepStmt = connection.prepareStatement(
                        "INSERT INTO IDN_XACML_POLICY_EDITOR_DATA (NAME, DATA, POLICY_ID, VERSION, TENANT_ID) " +
                                "VALUES (?, ?, ?, ?, ?)");
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
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }



    /**
     * @param policyId
     * @throws EntitlementException
     */
    public void removePolicy(String policyId) throws EntitlementException {
        String path = null;

        if (log.isDebugEnabled()) {
            log.debug("Removing entitlement policy");
        }

        try {
            path = PDPConstants.ENTITLEMENT_POLICY_PAP + policyId;
            if (!registry.resourceExists(path)) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to access an entitlement policy which does not exist");
                }
                return;
            }
            registry.delete(path);
        } catch (RegistryException e) {
            log.error("Error while removing entitlement policy " + policyId + " from PAP policy store", e);
            throw new EntitlementException("Error while removing policy " + policyId + " from PAP policy store");
        }
    }


    /**
     * This removes the given policy from the policy store
     *
     * @param policyId policyId
     * @throws EntitlementException throws, if fails
     */

    public void removePolicyFromNewRDBMS(String policyId) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (log.isDebugEnabled()) {
            log.debug("Removing entitlement policy");
        }
        try {

            //Find whether the policy is published or not
            PreparedStatement findPDPPresencePrepStmt = connection.prepareStatement(
                    "SELECT * FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND IS_IN_PDP=? AND TENANT_ID=?");
            findPDPPresencePrepStmt.setString(1, policyId);
            findPDPPresencePrepStmt.setInt(2, 1);
            findPDPPresencePrepStmt.setInt(3, tenantId);
            ResultSet rs1 = findPDPPresencePrepStmt.executeQuery();

            if (rs1.next()) {

                //Remove the unpublished versions of the policy from the database
                PreparedStatement removePolicyByIdAndVersionPrepStmt = connection.prepareStatement(
                        "DELETE FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND TENANT_ID=? AND IS_IN_PDP=?");
                removePolicyByIdAndVersionPrepStmt.setString(1, policyId);
                removePolicyByIdAndVersionPrepStmt.setInt(2, tenantId);
                removePolicyByIdAndVersionPrepStmt.setInt(3, 0);
                removePolicyByIdAndVersionPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyByIdAndVersionPrepStmt);

                //Remove the published version of the policy from the PAP (It is still present in PDP)
                PreparedStatement removePolicyFromPAPPrepStmt = connection.prepareStatement(
                        "UPDATE IDN_XACML_POLICY SET IS_IN_PAP=? WHERE POLICY_ID=? AND IS_IN_PDP=? AND TENANT_ID=?");
                removePolicyFromPAPPrepStmt.setInt(1, 0);
                removePolicyFromPAPPrepStmt.setString(2, policyId);
                removePolicyFromPAPPrepStmt.setInt(3, 1);
                removePolicyFromPAPPrepStmt.setInt(4, tenantId);
                removePolicyFromPAPPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyFromPAPPrepStmt);

            } else {
                //Remove the policy from the database
                PreparedStatement removePolicyPrepStmt = connection.prepareStatement(
                        "DELETE FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND TENANT_ID=?");
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
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    /**
     * This removes the given policy version from the policy store
     *
     * @param policyId policyId
     * @param version version
     * @throws EntitlementException throws, if fails
     */
    public void removePolicyByVersion(String policyId, int version) throws EntitlementException{

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (log.isDebugEnabled()) {
            log.debug("Removing entitlement policy version");
        }
        try {

            //Find whether the policy is published or not
            PreparedStatement findPDPPresencePrepStmt = connection.prepareStatement(
                    "SELECT * FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND IS_IN_PDP=? AND TENANT_ID=? AND VERSION=?");
            findPDPPresencePrepStmt.setString(1, policyId);
            findPDPPresencePrepStmt.setInt(2, 1);
            findPDPPresencePrepStmt.setInt(3, tenantId);
            findPDPPresencePrepStmt.setInt(4, version);
            ResultSet rs1 = findPDPPresencePrepStmt.executeQuery();

            if (rs1.next()) {

                //Remove the policy version from the PAP (It is still present in PDP)
                PreparedStatement removePolicyFromPAPPrepStmt = connection.prepareStatement(
                        "UPDATE IDN_XACML_POLICY SET IS_IN_PAP=? WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?");
                removePolicyFromPAPPrepStmt.setInt(1, 0);
                removePolicyFromPAPPrepStmt.setString(2, policyId);
                removePolicyFromPAPPrepStmt.setInt(3, version);
                removePolicyFromPAPPrepStmt.setInt(4, tenantId);
                removePolicyFromPAPPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(removePolicyFromPAPPrepStmt);

            } else {
                //Remove the policy version from the database
                PreparedStatement removePolicyPrepStmt = connection.prepareStatement(
                        "DELETE FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND TENANT_ID=? AND VERSION=?");
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
            log.error("Error while removing entitlement policy version " + policyId +" "+version+ " from PAP policy store", e);
            throw new EntitlementException("Error while removing policy version " + policyId +" "+version+ " from PAP policy store");
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

}
