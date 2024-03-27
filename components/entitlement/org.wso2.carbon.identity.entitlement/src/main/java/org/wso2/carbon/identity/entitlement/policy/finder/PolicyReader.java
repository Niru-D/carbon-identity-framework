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

package org.wso2.carbon.identity.entitlement.policy.finder;

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
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import java.nio.charset.Charset;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 * PDP policy reader
 */
public class PolicyReader {

    /**
     * logger
     */
    private static Log log = LogFactory.getLog(PolicyReader.class);

    /**
     * constructor
     *
     */
    public PolicyReader() {

    }

    /**
     * Reads given policyId as PolicyDTO
     *
     * @param policyId policy id
     * @return PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    public PolicyDTO readPolicy(String policyId) throws EntitlementException {

        PolicyDTO policy = null;
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
    public PolicyDTO[] readAllPolicies(boolean active, boolean order) throws EntitlementException {

        PolicyDTO[] policies = null;
        policies = getAllPolicies();

        if (policies == null) {
            return new PolicyDTO[0];
        }
        List<PolicyDTO> policyDTOList = new ArrayList<PolicyDTO>();
        for (PolicyDTO policy : policies) {
            if (active) {
                if (policy.isActive()) {
                    policyDTOList.add(policy);
                }
            } else {
                policyDTOList.add(policy);
            }
        }

        PolicyDTO[] policyDTOs = policyDTOList.toArray(new PolicyDTO[policyDTOList.size()]);

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
    public String[] getAllPolicyIds() throws EntitlementException {

        List<String> policyIDs = new ArrayList<String>();
        PolicyDTO[] policyDTOs = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        policyDTOs = getAllPolicies();
        for(PolicyDTO dto : policyDTOs){
            policyIDs.add(dto.getPolicyId());
        }

        return policyIDs.toArray(new String[policyIDs.size()]);
    }


    /**
     * This reads the policy combining algorithm
     *
     * @return policy combining algorithm as String
     * @throws EntitlementException throws
     */
    public String readPolicyCombiningAlgorithm() throws EntitlementException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getPolicyCombiningAlgoPrepStmt = null;
        ResultSet algorithm = null;

        try {
            getPolicyCombiningAlgoPrepStmt = connection.prepareStatement(
                    "SELECT * FROM IDN_XACML_CONFIG WHERE TENANT_ID=? AND CONFIG_KEY=?");
            getPolicyCombiningAlgoPrepStmt.setInt(1, tenantId);
            getPolicyCombiningAlgoPrepStmt.setString(2, "globalPolicyCombiningAlgorithm");
            algorithm = getPolicyCombiningAlgoPrepStmt.executeQuery();

            if(algorithm.next()){
                return algorithm.getString("CONFIG_VALUE");
            }else{
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
        PreparedStatement getAllPDPPolicy = null;
        ResultSet policy = null;
        PolicyDTO dto = new PolicyDTO();

        try {

            getAllPDPPolicy = connection.prepareStatement(
                    "SELECT * FROM IDN_XACML_POLICY WHERE TENANT_ID=? AND IS_IN_PDP=? AND POLICY_ID=?");
            getAllPDPPolicy.setInt(1, tenantId);
            getAllPDPPolicy.setInt(2, 1);
            getAllPDPPolicy.setString(3, policyId);
            policy = getAllPDPPolicy.executeQuery();

            if(policy.next()){
                String policyString = policy.getString("POLICY");
                AbstractPolicy absPolicy = PAPPolicyReader.getInstance(null).getPolicy(policyString);
                dto.setPolicyId(absPolicy.getId().toASCIIString());
                dto.setPolicy(policyString);
                int policyOrder = policy.getInt("POLICY_ORDER");
                dto.setPolicyOrder(policyOrder);
                int isActiveInt = policy.getInt("IS_ACTIVE");
                dto.setActive((isActiveInt != 0));
                dto.setPolicyType(policy.getString("POLICY_TYPE"));

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_ATTRIBUTE WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?",
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
                getPolicyMetaDataPrepStmt.setString(1, absPolicy.getId().toASCIIString());
                getPolicyMetaDataPrepStmt.setInt(2, policy.getInt("VERSION"));
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

            }else{
                return null;
            }
            return dto;

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy : " + policyId, e);
            throw new EntitlementException("Error while retrieving entitlement policy : " + policyId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policy, getAllPDPPolicy);
        }
    }


    /**
     * This returns all the policies as PolicyDTOs.
     *
     * @return policies as PolicyDTO[]
     * @throws EntitlementException throws if fails
     */
    private PolicyDTO[] getAllPolicies() throws EntitlementException {

        List<PolicyDTO> policies = new ArrayList<PolicyDTO>();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement getAllPDPPolicies = null;
        ResultSet policySet = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all entitlement policies");
        }

        try {

          getAllPDPPolicies = connection.prepareStatement(
                  "SELECT * FROM IDN_XACML_POLICY WHERE TENANT_ID=? AND IS_IN_PDP=?");
          getAllPDPPolicies.setInt(1, tenantId);
          getAllPDPPolicies.setInt(2, 1);
          policySet = getAllPDPPolicies.executeQuery();

          if(policySet.next()){
            do{
                String policy = policySet.getString("POLICY");
                AbstractPolicy absPolicy = PAPPolicyReader.getInstance(null).getPolicy(policy);
                PolicyDTO dto = new PolicyDTO();
                dto.setPolicyId(absPolicy.getId().toASCIIString());
                dto.setPolicy(policy);
                int policyOrder = policySet.getInt("POLICY_ORDER");
                dto.setPolicyOrder(policyOrder);
                int isActiveInt = policySet.getInt("IS_ACTIVE");
                dto.setActive((isActiveInt != 0));
                dto.setPolicyType(policySet.getString("POLICY_TYPE"));

                //Get policy references
                List<String> policyReferences = new ArrayList<String>();
                PreparedStatement getPolicyRefsPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_REFERENCE WHERE TENANT_ID=? AND POLICY_ID=? AND VERSION=?");
                getPolicyRefsPrepStmt.setInt(1, tenantId);
                getPolicyRefsPrepStmt.setString(2, absPolicy.getId().toASCIIString());
                getPolicyRefsPrepStmt.setInt(3, policySet.getInt("VERSION"));
                ResultSet policyRefs = getPolicyRefsPrepStmt.executeQuery();

                if(policyRefs.next()){
                    do{
                        policyReferences.add(policyRefs.getString("REFERENCE"));
                    } while(policyRefs.next());
                }
                dto.setPolicyIdReferences(policyReferences.toArray(new String[policyReferences.size()]));
                IdentityDatabaseUtil.closeResultSet(policyRefs);
                IdentityDatabaseUtil.closeStatement(getPolicyRefsPrepStmt);

                //Get policy set references
                List<String> policySetReferences = new ArrayList<String>();
                PreparedStatement getPolicySetRefsPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_SET_REFERENCE WHERE TENANT_ID=? AND POLICY_ID=? AND VERSION=?");
                getPolicySetRefsPrepStmt.setInt(1, tenantId);
                getPolicySetRefsPrepStmt.setString(2, absPolicy.getId().toASCIIString());
                getPolicySetRefsPrepStmt.setInt(3, policySet.getInt("VERSION"));
                ResultSet policySetRefs = getPolicySetRefsPrepStmt.executeQuery();

                if(policySetRefs.next()){
                    do{
                        policySetReferences.add(policySetRefs.getString("SET_REFERENCE"));
                    } while(policySetRefs.next());
                }
                dto.setPolicySetIdReferences(policySetReferences.toArray(new String[policySetReferences.size()]));
                IdentityDatabaseUtil.closeResultSet(policySetRefs);
                IdentityDatabaseUtil.closeStatement(getPolicySetRefsPrepStmt);

                //Get policy metadata
                PreparedStatement getPolicyMetaDataPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_POLICY_ATTRIBUTE WHERE POLICY_ID=? AND VERSION=? AND TENANT_ID=?",
                        ResultSet.TYPE_SCROLL_INSENSITIVE,
                        ResultSet.CONCUR_READ_ONLY
                );
                getPolicyMetaDataPrepStmt.setString(1, absPolicy.getId().toASCIIString());
                getPolicyMetaDataPrepStmt.setInt(2, policySet.getInt("VERSION"));
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

                policies.add(dto);

            } while (policySet.next());
          }else{
              if (log.isDebugEnabled()) {
                  log.debug("Trying to access an entitlement policy which does not exist");
              }
              return null;
          }

          return policies.toArray(new PolicyDTO[policies.size()]);

        } catch (SQLException e) {
            log.error("Error while retrieving entitlement policy", e);
            throw new EntitlementException("Error while retrieving entitlement policies", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, policySet, getAllPDPPolicies);
        }
    }

}
