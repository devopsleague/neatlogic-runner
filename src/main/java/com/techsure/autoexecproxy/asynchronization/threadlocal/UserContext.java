package com.techsure.autoexecproxy.asynchronization.threadlocal;


import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import com.techsure.autoexecproxy.dto.UserVo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class UserContext implements Serializable {
	private static final long serialVersionUID = -578199115176786224L;
	@JSONField(serialize = false)
	private final transient static ThreadLocal<UserContext> instance = new ThreadLocal<UserContext>();
	@JSONField(serialize = false)
	private transient HttpServletRequest request;
	@JSONField(serialize=false)
	private transient HttpServletResponse response;
	private String tenant;
	private String userName;
	private String userId;
	private String userUuid;
	private String timezone = "+8:00";
	private String token;
	private List<String> roleUuidList = new ArrayList<>();
	
	public static UserContext init(UserContext _userContext) {
		UserContext context = new UserContext();
		if (_userContext != null) {
			context.setUserId(_userContext.getUserId());
			context.setUserUuid(_userContext.getUserUuid());
			context.setUserName(_userContext.getUserName());
			context.setTenant(_userContext.getTenant());
			context.setTimezone(_userContext.getTimezone());
			context.setToken(_userContext.getToken());
			// context.setRequest(_userContext.getRequest());
			// context.setResponse(_userContext.getResponse());
			context.setRoleUuidList(_userContext.getRoleUuidList());
		}
		instance.set(context);
		return context;
	}

	public static UserContext init(JSONObject jsonObj, String token, String timezone, HttpServletRequest request, HttpServletResponse response) {
		UserContext context = new UserContext();
		context.setUserId(jsonObj.getString("userid"));
		context.setUserUuid(jsonObj.getString("useruuid"));
		context.setUserName(jsonObj.getString("username"));
		context.setTenant(jsonObj.getString("tenant"));
		context.setRequest(request);
		context.setToken(token);
		context.setResponse(response);
		context.setTimezone(timezone);
		JSONArray roleList = jsonObj.getJSONArray("rolelist");
		if (roleList != null && roleList.size() > 0) {
			for (int i = 0; i < roleList.size(); i++) {
				context.addRole(roleList.getString(i));
			}
		}
		instance.set(context);
		return context;
	}

	public static UserContext init(UserVo userVo, String timezone, HttpServletRequest request, HttpServletResponse response) {
		UserContext context = new UserContext();
		context.setUserId(userVo.getUserId());
		context.setUserUuid(userVo.getUuid());
		context.setUserName(userVo.getUserName());
		context.setTenant(userVo.getTenant());
		context.setToken(userVo.getAuthorization());
		context.setRequest(request);
		context.setResponse(response);
		context.setTimezone(timezone);
		instance.set(context);
		return context;
	}

	public static UserContext init(UserVo userVo, String timezone) {
		UserContext context = new UserContext();
		context.setUserId(userVo.getUserId());
		context.setUserUuid(userVo.getUuid());
		context.setUserName(userVo.getUserName());
		context.setTenant(userVo.getTenant());
		context.setToken(userVo.getAuthorization());
		context.setTimezone(timezone);
		instance.set(context);
		return context;
	}

	public void addRole(String role) {
		if (!roleUuidList.contains(role)) {
			roleUuidList.add(role);
		}
	}

	public String getTimezone() {
		return timezone;
	}

	public void setTimezone(String timezone) {
		this.timezone = timezone;
	}

	private UserContext() {

	}

	public static UserContext get() {
		return instance.get();
	}

	public void release() {
		instance.remove();
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getUserId() {
		return userId;
	}

	public String getUserId(boolean need) {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserUuid() {
		return userUuid;
	}
	
	public String getUserUuid(boolean need) {
		return userUuid;
	}

	public void setUserUuid(String userUuid) {
		this.userUuid = userUuid;
	}

	public List<String> getRoleUuidList() {
		return roleUuidList;
	}

	public void setRoleUuidList(List<String> roleUuidList) {
		this.roleUuidList = roleUuidList;
	}

	public String getTenant() {
		return tenant;
	}

	public void setTenant(String tenant) {
		this.tenant = tenant;
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}

	public HttpServletResponse getResponse() {
		return response;
	}

	public void setResponse(HttpServletResponse response) {
		this.response = response;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
}
