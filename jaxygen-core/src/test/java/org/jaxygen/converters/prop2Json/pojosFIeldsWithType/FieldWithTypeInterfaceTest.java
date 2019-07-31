/*
 * Copyright 2017 xnet.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jaxygen.converters.prop2Json.pojosFIeldsWithType;

import org.jaxygen.annotations.HasImplementation;
import org.jaxygen.converters.prop2Json.pojos.Impl2TestPojo;
import org.jaxygen.converters.prop2Json.pojos.ImplTestPojo;
import org.jaxygen.customimplementation.Entry;
import org.jaxygen.customimplementation.ImplementationClassType;

/**
 *
 * @author jknast
 */
@ImplementationClassType(typeFieldName = "myType",
        typeToClassMap = {
            @Entry(type = "TYPE_1", clazz = FieldWithTypeImplTestPojo_1.class)
            ,@Entry(type = "TYPE_2", clazz = FieldWithTypeImplTestPojo_2.class)
        })
@HasImplementation(implementations = {ImplTestPojo.class, Impl2TestPojo.class})
public interface FieldWithTypeInterfaceTest {

    public MyType getMyType();
}
