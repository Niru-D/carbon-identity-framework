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
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.dto.PolicyDTO;
import org.wso2.carbon.registry.core.Resource;

import java.sql.SQLException;

public class PAPPolicyStoreManager {

    private static final Log log = LogFactory.getLog(PAPPolicyStoreManager.class);
    private PAPPolicyStore store;
    private PAPPolicyStoreReader storeReader;

    public PAPPolicyStoreManager() {
        store = new PAPPolicyStore();
        storeReader = new PAPPolicyStoreReader(store);
    }

    public void addOrUpdatePolicy(PolicyDTO policy) throws EntitlementException {
        store.addOrUpdatePolicy(policy);
    }

    public void removePolicy(String policyId) throws EntitlementException {
        store.removePolicy(policyId);
    }

    public void removePolicyByVersion(String policyId, int version) throws EntitlementException{
        store.removePolicyByVersion(policyId, version);
    }

    public String[] getPolicyIds() throws EntitlementException {
        return store.getAllPolicyIds();
    }

    public PolicyDTO getPolicy(String policyId) throws EntitlementException {
        return storeReader.readPolicyDTO(policyId);
    }

    public boolean isExistPolicy(String policyId) {
        return storeReader.isExistPolicy(policyId);
    }

    public PolicyDTO getLightPolicy(String policyId) throws EntitlementException {
        return storeReader.readLightPolicyDTO(policyId);
    }

    public PolicyDTO getMetaDataPolicy(String policyId) throws EntitlementException {
        return storeReader.readMetaDataPolicyDTO(policyId);
    }

    public PolicyDTO[] getAllLightPolicyDTOs() throws EntitlementException {
        return storeReader.readAllLightPolicyDTOs();
    }
}
