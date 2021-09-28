package com.techsure.autoexecproxy.constvalue;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.util.List;

public enum TagentAction {
    GETLOGS("getlogs", "获取日志"),
    GETCONFIG("getConfig", "获取配置"),
    SAVECONFIG("saveConfig", "保存日志"),
    RELOAD("reload", "重启");
    private final String value;
    private final String text;

    TagentAction(String value, String text) {
        this.value = value;
        this.text = text;
    }

    public String getValue() {
        return value;
    }

    public String getText() {
        return text;
    }


    public List getValueTextList() {
        JSONArray array = new JSONArray();
        for (TagentAction action : values()) {
            array.add(new JSONObject() {
                {
                    this.put("value", action.getValue());
                    this.put("text", action.getText());
                }
            });
        }
        return array;
    }
}
