/*
 * Copyright(c) 2023 NeatLogic Co., Ltd. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.neatlogic.autoexecrunner.exception;

import com.neatlogic.autoexecrunner.exception.core.ApiRuntimeException;

public class TenantNotFoundException extends ApiRuntimeException {

    public TenantNotFoundException(String tenant) {
        super("租户：" + tenant + "不存在");
    }

    public TenantNotFoundException() {
        super("检测不到租户信息，无法进行下一步操作");
    }

    public TenantNotFoundException(Long tenantId) {
        super("租户id：" + tenantId + "不存在");
    }
}
