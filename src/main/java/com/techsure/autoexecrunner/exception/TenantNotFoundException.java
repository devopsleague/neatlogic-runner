/*
 * Copyright(c) 2022 TechSure Co., Ltd. All Rights Reserved.
 * 本内容仅限于深圳市赞悦科技有限公司内部传阅，禁止外泄以及用于其他的商业项目。
 */

package com.techsure.autoexecrunner.exception;

import com.techsure.autoexecrunner.exception.core.ApiRuntimeException;

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
