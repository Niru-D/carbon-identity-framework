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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.balana.AbstractPolicy;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.AttributeDTO;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.pap.PAPPolicyReader;


public class PAPPolicyStoreReader {

    // the optional logger used for error reporting
    private static Log log = LogFactory.getLog(PAPPolicyStoreReader.class);

    private PAPPolicyStore store;

    /**
     * @param store
     */
    public PAPPolicyStoreReader(PAPPolicyStore store) {
        this.store = store;
    }


    /**
     * @param policyId
     * @param finder
     * @return
     * @throws EntitlementException
     */
    public synchronized AbstractPolicy readPolicy(String policyId, PolicyFinder finder)
            throws EntitlementException {

        PolicyDTO dto = store.getPolicy(policyId);
        if (dto != null) {
            String policy = dto.getPolicy();
            return PAPPolicyReader.getInstance(null).getPolicy(policy);
        }
        return null;
    }


    /**
     * Reads All policies as Light Weight PolicyDTO
     *
     * @return Array of PolicyDTO but does not contain XACML policy and attribute metadata
     * @throws EntitlementException throws, if fails
     */
    public PolicyDTO[] readAllLightPolicyDTOs() throws EntitlementException {

        return store.getAllPolicies();

    }


    /**
     * Reads PolicyDTO for given policy id
     *
     * @param policyId policy id
     * @return PolicyDTO
     * @throws EntitlementException throws, if fails
     */
    public PolicyDTO readPolicyDTO(String policyId) throws EntitlementException {

        PolicyDTO dto = store.getPolicy(policyId);
        if (dto == null) {
            log.error("Policy does not exist in the system with id " + policyId);
            throw new EntitlementException("Policy does not exist in the system with id " + policyId);
        }
        return dto;
    }


    /**
     * Checks whether policy exists for the given policy id
     *
     * @param policyId policy id
     * @return true of false
     */
    public boolean isExistPolicy(String policyId) {

        PolicyDTO dto = null;
        try {
            dto = store.getPolicy(policyId);
            if (dto != null) {
                return true;
            }
        } catch (EntitlementException e) {
            //ignore
        }
        return false;
    }


    /**
     * Reads Light Weight PolicyDTO for given policy id
     *
     * @param policyId policy id
     * @return PolicyDTO but don not contains XACML policy and attribute meta data
     * @throws EntitlementException throws, if fails
     */
    public PolicyDTO readLightPolicyDTO(String policyId) throws EntitlementException {

        PolicyDTO dto = store.getPolicy(policyId);
        if (dto == null) {
            return null;
        }
        dto.setPolicy(null);
        AttributeDTO[] arr = new AttributeDTO[0];
        dto.setAttributeDTOs(arr);
        String[] arr2 = new String[0];
        dto.setPolicyEditorData(arr2);
        return dto;
    }


    /**
     * Reads Light Weight PolicyDTO with Attribute metadata for given policy id
     *
     * @param policyId policy id
     * @return PolicyDTO but don not contains XACML policy
     * @throws EntitlementException throws, if fails
     */
    public PolicyDTO readMetaDataPolicyDTO(String policyId) throws EntitlementException {

        PolicyDTO dto = store.getPolicy(policyId);
        if(dto == null){
            return null;
        }
        dto.setPolicy(null);
        return dto;

    }


}
