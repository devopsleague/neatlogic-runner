package com.neatlogic.autoexecrunner.exception;


import com.neatlogic.autoexecrunner.exception.core.ApiRuntimeException;

public class ParamValueTooLongException extends ApiRuntimeException {
	private static final long serialVersionUID = 5528197166107887380L;

	public ParamValueTooLongException(String paramName, int valueLength, int maxLength) {
		super("参数：“" + paramName + "”允许最大长度是" + maxLength + "个字符");
	}
}
