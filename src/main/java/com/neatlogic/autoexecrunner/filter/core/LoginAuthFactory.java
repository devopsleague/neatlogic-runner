/*Copyright (C) 2024  深圳极向量科技有限公司 All Rights Reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.*/

package com.neatlogic.autoexecrunner.filter.core;


import com.neatlogic.autoexecrunner.applicationlistener.ApplicationListenerBase;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
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
