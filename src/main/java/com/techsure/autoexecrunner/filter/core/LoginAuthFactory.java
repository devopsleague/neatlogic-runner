/*
 * Copyright(c) 2021 TechSure Co., Ltd. All Rights Reserved.
 * 本内容仅限于深圳市赞悦科技有限公司内部传阅，禁止外泄以及用于其他的商业项目。
 */

package com.techsure.autoexecrunner.filter.core;


import com.techsure.autoexecrunner.applicationlistener.ApplicationListenerBase;
import com.techsure.autoexecrunner.common.RootComponent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;

import java.util.HashMap;
import java.util.Map;

@RootComponent
public class LoginAuthFactory extends ApplicationListenerBase {
    private static final Map<String, ILoginAuthHandler> loginAuthMap = new HashMap<>();


    public static ILoginAuthHandler getLoginAuth(String type) {
        return loginAuthMap.get(type.toUpperCase());
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        ApplicationContext context = event.getApplicationContext();
        Map<String, ILoginAuthHandler> myMap = context.getBeansOfType(ILoginAuthHandler.class);
        for (Map.Entry<String, ILoginAuthHandler> entry : myMap.entrySet()) {
            ILoginAuthHandler authAuth = entry.getValue();
            loginAuthMap.put(authAuth.getType().toUpperCase(), authAuth);
        }

    }

    @Override
    protected void myInit() {
        // TODO Auto-generated method stub

    }

}
