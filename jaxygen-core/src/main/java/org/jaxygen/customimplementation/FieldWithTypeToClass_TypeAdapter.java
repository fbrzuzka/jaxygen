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
package org.jaxygen.customimplementation;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import org.jaxygen.exceptions.NoDefinitionOfImplementationException;

/**
 *
 * @author xnet
 */
public class FieldWithTypeToClass_TypeAdapter extends TypeAdapter<Object> {

    final private TypeAdapter<JsonElement> elementAdapter;
    final private Gson gson;
    final private String typeFieldName;
//    final private Enum<? extends TypeToClass> typeToClassResolverClass;
    final private Entry[] entrys;

    public FieldWithTypeToClass_TypeAdapter(Gson gson, ImplementationClassType annotation) {
        this.gson = gson;
        this.elementAdapter = gson.getAdapter(JsonElement.class);
        this.typeFieldName = annotation.typeFieldName();
//        this.typeToClassResolverClass = annotation.typeToClassResolver();
        this.entrys = annotation.typeToClassMap();
    }

    public Class getByName(String name) {
        for (Entry entry : entrys) {
            if (entry.type().equals(name)) {
                return entry.clazz();
            }
        }
        return null;
    }

    //serialize function
    @Override
    public void write(JsonWriter out, Object value) throws IOException {
        if (value == null) {
            elementAdapter.write(out, JsonNull.INSTANCE);
        } else {
            TypeAdapter adapter = gson.getAdapter(value.getClass());
            JsonElement ret = adapter.toJsonTree(value);
            elementAdapter.write(out, ret);
        }
    }

    //deserialize function
    @Override
    public Object read(JsonReader in) throws IOException {
        JsonElement element = elementAdapter.read(in);
        final JsonObject convertable = element.getAsJsonObject();
        final JsonPrimitive typeValue = (JsonPrimitive) convertable.get(typeFieldName);
        if (typeValue == null) {
            throw new NoDefinitionOfImplementationException("There is no key '" + typeFieldName + "' in json. Keys are: " + convertable.keySet());
        }
        final String type = typeValue.getAsString();
//        TypeToClass typeToClassResolver = instantiate(typeToClassResolverClass);
//        Class implementationClass = typeToClassResolver.getImplementationClass(type);
        Class implementationClass = getByName(type);

        TypeAdapter adapter = gson.getAdapter(implementationClass);
        Object ret = adapter.fromJsonTree(convertable);
        return ret;
    }

    public Class getClassInstance(String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException cnfe) {
            throw new JsonParseException(cnfe.getMessage());
        }
    }

//    public <T> T instantiate(Class<T> clazz) {
//        try {
//            T instance = clazz.newInstance();
//            return instance;
//        } catch (InstantiationException | IllegalAccessException ex) {
//            throw new NoDefinitionOfImplementationException("Error in instantiating typeToClassResolver: " + clazz.getCanonicalName(), ex);
//        }
//
//    }
}
