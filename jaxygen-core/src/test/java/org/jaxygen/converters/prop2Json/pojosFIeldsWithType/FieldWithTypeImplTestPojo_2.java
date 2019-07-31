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

import java.util.ArrayList;
import java.util.List;
import org.assertj.core.util.Lists;

/**
 *
 * @author jknast
 */
@lombok.Getter
@lombok.Setter
@lombok.NoArgsConstructor
public class FieldWithTypeImplTestPojo_2 implements FieldWithTypeInterfaceTest {

    private String bar2;
    private String foo2;
    private List<String> list2 = new ArrayList();
    private MyType myType = MyType.TYPE_2;


    public FieldWithTypeImplTestPojo_2(String bar2, String foo2, String... arrValues) {
        this.bar2 = bar2;
        this.foo2 = foo2;
        if (arrValues != null) {
            list2.addAll(Lists.newArrayList(arrValues));
        }
    }
}
