package com.techsure.autoexecproxy.restful.annotation;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Input {
	Param[] value();
}
