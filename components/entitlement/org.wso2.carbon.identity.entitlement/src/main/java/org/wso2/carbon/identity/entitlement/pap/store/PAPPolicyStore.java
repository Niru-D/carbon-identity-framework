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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementClientException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.dao.impl.ApplicationDAOImpl;
import org.wso2.carbon.identity.application.mgt.dao.impl.ApplicationMgtDBQueries;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.AttributeDTO;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.identity.entitlement.policy.PolicyAttributeBuilder;
import org.wso2.carbon.ndatasource.common.DataSourceException;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import javax.naming.NamingException;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import javax.naming.Context;
import javax.naming.InitialContext;
import org.wso2.carbon.ndatasource.core.CarbonDataSource;

import javax.xml.stream.XMLStreamException;
import java.sql.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Error.APPLICATION_ALREADY_EXISTS;

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
        String path = null;
        Collection collection = null;
        List<String> resources = new ArrayList<String>();
        String[] children = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        try {
            path = PDPConstants.ENTITLEMENT_POLICY_PAP;

            if (!registry.resourceExists(path)) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to access an entitlement policy which does not exist");
                }
                return null;
            }
            collection = (Collection) registry.get(path);
            children = collection.getChildren();
            for (String child : children) {
                String[] resourcePath = child.split("/");
                if (resourcePath != null && resourcePath.length > 0) {
                    resources.add(resourcePath[resourcePath.length - 1]);
                }
            }

        } catch (RegistryException e) {
            log.error("Error while retrieving all entitlement policy identifiers from PAP policy store", e);
            throw new EntitlementException("Error while retrieving entitlement policy " +
                                           "identifiers from PAP policy store");
        }

        return resources.toArray(new String[resources.size()]);
    }


    /**
     * This returns given policy as Registry resource
     *
     * @param policyId   policy id
     * @param collection
     * @return policy as Registry resource
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
            log.debug("Creating or updating entitlement policy-------------- test-original-method");
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

    public void addOrUpdatePolicyToNewRDBMS(PolicyDTO policy, String policyId)
            throws EntitlementException {

        boolean newPolicy = false;
        OMElement omElement = null;
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        if (log.isDebugEnabled()) {
            log.debug("Creating or updating entitlement policy");
        }

        if (policy == null || policyId == null) {
            log.error("Error while creating or updating entitlement policy: " +
                    "Policy DTO or Policy Id can not be null");
            throw new EntitlementException("Invalid Entitlement Policy. Policy or policyId can not be Null");
        }

        try {

            //Find policy order
            int finalPolicyOrder;
            PreparedStatement getPolicyCountPrepStmt =
                    connection.prepareStatement("SELECT COUNT(*) AS COUNT FROM POLICY WHERE TENANT_ID=?");
            getPolicyCountPrepStmt.setInt(1,tenantId);
            ResultSet rs = getPolicyCountPrepStmt.executeQuery();

            int noOfPolicies = 0;
            if (rs.next()) {
                noOfPolicies = rs.getInt("COUNT");
            }
            if (policy.getPolicyOrder() > 0) {
                finalPolicyOrder = policy.getPolicyOrder();
            } else {
                int policyOrder = 1;
                if (noOfPolicies != 0) {
                    policyOrder = policyOrder + noOfPolicies;
                }
                finalPolicyOrder = policyOrder;
            }

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

            //Find policy references and policy set references
            String policyReferences = "";
            String policySetReferences = "";

            if (omElement != null) {
                Iterator iterator1 = omElement.getChildrenWithLocalName(PDPConstants.
                        POLICY_REFERENCE);
                if (iterator1 != null) {
                    while (iterator1.hasNext()) {
                        OMElement policyReference = (OMElement) iterator1.next();
                        if (!"".equals(policyReferences)) {
                            policyReferences = policyReferences + PDPConstants.ATTRIBUTE_SEPARATOR
                                    + policyReference.getText();
                        } else {
                            policyReferences = policyReference.getText();
                        }
                    }
                }
                Iterator iterator2 = omElement.getChildrenWithLocalName(PDPConstants.
                        POLICY_SET_REFERENCE);
                if (iterator2 != null) {
                    while (iterator1.hasNext()) {
                        OMElement policySetReference = (OMElement) iterator2.next();
                        if (!"".equals(policySetReferences)) {
                            policySetReferences = policySetReferences + PDPConstants.ATTRIBUTE_SEPARATOR
                                    + policySetReference.getText();
                        } else {
                            policySetReferences = policySetReference.getText();
                        }
                    }
                }
            }

            //Find policy editor type
            String policyEditorType = null;
            if (policy.getPolicyEditor() != null && !policy.getPolicyEditor().trim().isEmpty()) {
                policyEditorType = policy.getPolicyEditor().trim();
            }

            //Write a new policy
            PreparedStatement createPolicyPrepStmt = null;
            int active = policy.isActive() ? 1: 0;
            int promote = policy.isPromote() ? 1: 0;

            try {
                createPolicyPrepStmt = connection.prepareStatement(
                        "INSERT INTO POLICY (POLICY_ID, VERSION, TENANT_ID, IS_IN_PDP, IS_IN_PAP, POLICY, " +
                                "IS_ACTIVE, POLICY_TYPE, POLICY_EDITOR, POLICY_ORDER, LAST_MODIFIED_TIME, " +
                                "LAST_MODIFIED_USER, POLICY_REFERENCES, POLICY_SET_REFERENCES) VALUES " +
                                "(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                createPolicyPrepStmt.setString(1, policyId);
                createPolicyPrepStmt.setInt(2, Integer.parseInt(policy.getVersion()));
                createPolicyPrepStmt.setInt(3, tenantId);
                createPolicyPrepStmt.setInt(4, promote);
                createPolicyPrepStmt.setString(5, policy.getPolicy());
                createPolicyPrepStmt.setInt(6, active);
                createPolicyPrepStmt.setString(7, policyType);
                createPolicyPrepStmt.setString(8, policyEditorType);
                createPolicyPrepStmt.setInt(9, finalPolicyOrder);
                createPolicyPrepStmt.setString(10, Long.toString(System.currentTimeMillis()));
                createPolicyPrepStmt.setString
                        (11, CarbonContext.getThreadLocalCarbonContext().getUsername());
                createPolicyPrepStmt.setString(12, policyReferences);
                createPolicyPrepStmt.setString(13, policySetReferences);

//                IdentityDatabaseUtil.commitTransaction(connection);
                createPolicyPrepStmt.executeUpdate();

            } catch (SQLException e) {
//                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new EntitlementException("Error while creating policy", e);
            } finally {
                assert createPolicyPrepStmt != null;
                createPolicyPrepStmt.close();
            }

            //Write attributes of the policy
            PreparedStatement createAttributesPrepStmt = null;
            try {
                if(properties != null) {
                    createAttributesPrepStmt = connection.prepareStatement(
                            "INSERT INTO ATTRIBUTE (NAME, VALUE, POLICY_ID, VERSION, TENANT_ID) VALUES " +
                                    "(?, ?, ?, ?, ?)");

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
                }
            } catch (SQLException e) {
                throw new EntitlementException("Error while writing policy attributes", e);
            }finally {
                assert createAttributesPrepStmt != null;
                createAttributesPrepStmt.close();
            }

            //Write policy editor data
            PreparedStatement createPolicyEditorDataPrepStmt = null;
            String[] policyMetaData = policy.getPolicyEditorData();
            try {
                if(policyMetaData != null && policyMetaData.length > 0) {
                    createPolicyEditorDataPrepStmt = connection.prepareStatement(
                            "INSERT INTO POLICY_EDITOR_DATA (NAME, DATA, POLICY_ID, VERSION, TENANT_ID) VALUES " +
                                    "(?, ?, ?, ?, ?)");

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
                }
            } catch (SQLException e) {
                throw new EntitlementException("Error while writing policy editor data", e);
            }finally {
                assert createPolicyEditorDataPrepStmt != null;
                createPolicyEditorDataPrepStmt.close();
            }

        } catch (SQLException e) {
            throw new EntitlementException("Error while adding or updating entitlement policy in policy store");
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

    public void removePolicyFromNewRDBMS(String policyId) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (log.isDebugEnabled()) {
            log.debug("Removing entitlement policy");
        }
        try {

            //Find whether the policy is published or not
            PreparedStatement findPDPPresencePrepStmt = connection.prepareStatement(
                    "SELECT * FROM POLICY WHERE POLICY_ID=? AND IS_IN_PDP=? AND TENANT_ID=?");
            findPDPPresencePrepStmt.setString(1, policyId);
            findPDPPresencePrepStmt.setInt(2, 1);
            findPDPPresencePrepStmt.setInt(3, tenantId);
            ResultSet rs1 = findPDPPresencePrepStmt.executeQuery();

            if (rs1.next()) {

                //Remove the unpublished versions of the policy from the database
                PreparedStatement removePolicyByIdAndVersionPrepStmt = connection.prepareStatement(
                        "DELETE FROM POLICY WHERE POLICY_ID=? AND TENANT_ID=? AND IS_IN_PDP=?");
                removePolicyByIdAndVersionPrepStmt.setString(1, policyId);
                removePolicyByIdAndVersionPrepStmt.setInt(2, tenantId);
                removePolicyByIdAndVersionPrepStmt.setInt(3, 0);
                removePolicyByIdAndVersionPrepStmt.executeUpdate();

                //Remove the published version of the policy from the PAP (It is still present in PDP)
                PreparedStatement removePolicyFromPAPPrepStmt = connection.prepareStatement(
                        "UPDATE POLICY SET IS_IN_PAP=? WHERE POLICY_ID=? AND IS_IN_PDP=? AND TENANT_ID=?");
                removePolicyFromPAPPrepStmt.setInt(1, 0);
                removePolicyFromPAPPrepStmt.setString(2, policyId);
                removePolicyFromPAPPrepStmt.setInt(3, 1);
                removePolicyFromPAPPrepStmt.setInt(4, tenantId);
                removePolicyFromPAPPrepStmt.executeUpdate();

            } else {
                //Remove the policy from the database
                PreparedStatement removePolicyPrepStmt = connection.prepareStatement(
                        "DELETE FROM POLICY WHERE POLICY_ID=? AND TENANT_ID=?");
                removePolicyPrepStmt.setString(1, policyId);
                removePolicyPrepStmt.setInt(2, tenantId);
                removePolicyPrepStmt.executeUpdate();
            }

        } catch (SQLException e) {
            log.error("Error while removing entitlement policy " + policyId + " from PAP policy store", e);
            throw new EntitlementException("Error while removing policy " + policyId + " from PAP policy store");
        }
    }


}
