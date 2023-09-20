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
package com.neatlogic.autoexecrunner.tagent.handler;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.neatlogic.autoexecrunner.common.config.Config;
import com.neatlogic.autoexecrunner.constvalue.TagentAction;
import com.neatlogic.autoexecrunner.exception.tagent.TagentActionFailedException;
import com.neatlogic.autoexecrunner.exception.tagent.TagentConfigGetFailedException;
import com.neatlogic.autoexecrunner.tagent.TagentHandlerBase;
import com.neatlogic.autoexecrunner.util.RC4Util;
import com.neatlogic.tagent.client.TagentClient;
import org.apache.commons.collections4.MapUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Properties;

/**
 * @author longrf
 * @date 2022/11/3 11:15
 */

public class TagentConfigBatchSaveHandler extends TagentHandlerBase {

    Logger logger = LoggerFactory.getLogger(TagentConfigBatchSaveHandler.class);

    @Override
    public String getName() {
        return TagentAction.BATCH_SAVE_CONFIG.getValue();
    }

    @Override
    public JSONObject execute(JSONObject param) {
        JSONObject result = new JSONObject();

        Map<String, String> configKeyValueMap = (Map<String, String>) JSON.parse(param.getString("configKeyValueString"));
        if (MapUtils.isEmpty(configKeyValueMap)) {
            return result;
        }
        try {
            String credential = RC4Util.decrypt(param.getString("credential"));
            TagentClient tagentClient = new TagentClient(param.getString("ip"), Integer.parseInt(param.getString("port")), credential, 3000, 30000);

            //下载tagent.conf文件
            TagentResultHandler pathHandler = new TagentResultHandler();
            int execStatus = -1;
            tagentClient.execCmd("echo %TAGENT_HOME% ", null, 10000, pathHandler);
            String path = JSONObject.parseObject(pathHandler.getContent()).getJSONArray("std").getString(0).trim().replaceAll("\n", "").replaceAll("\\/", "\\\\");
            TagentResultHandler handler = new TagentResultHandler();
            execStatus = tagentClient.download("$TAGENT_HOME/conf/tagent.conf", Config.AUTOEXEC_HOME() + File.separator + path, null, false, false, handler);

            //tagent.conf转properties
            if (execStatus == 0) {
                byte[] fileCharArray = handler.getFileByteArray();
                InputStream input = new ByteArrayInputStream(fileCharArray);
                Properties properties = new Properties();
                InputStream in = null;
                try {
                    in = new BufferedInputStream(input);
                    properties.load(in);
                } catch (IOException e) {
                    logger.error("tagent.conf转properties失败：" + e.getMessage(), e);
                } finally {
                    try {
                        if (in != null) {
                            in.close();
                        }
                    } catch (IOException e) {
                        logger.error(e.getMessage(), e);
                    }
                }
                //赋值
                properties.putAll(configKeyValueMap);
                //去掉{}号，并加换行符
                String newConfigString = properties.toString().substring(1, properties.toString().length() - 1);
                newConfigString = newConfigString.replaceAll(",", "\n");

                //上传文件
                InputStream inputConfig = new ByteArrayInputStream(newConfigString.trim().getBytes(StandardCharsets.UTF_8));
                tagentClient.upload(inputConfig, "tagent.conf", "$TAGENT_HOME/conf/", null, false);
                //重启
                tagentClient.reload();
                result.put("Data", "send command succeed");
            } else {
                throw new TagentConfigGetFailedException();
            }
        } catch (Exception e) {
            logger.error("exec batchSaveConfig cmd error ,exception ：" + param, e);
            throw new TagentActionFailedException(e.getMessage());
        }
        return result;
    }
}
