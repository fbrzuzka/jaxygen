package org.jaxygen.invoker;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.jaxygen.annotations.ClientIp;
import org.jaxygen.annotations.NetAPI;
import org.jaxygen.annotations.RequestURL;
import org.jaxygen.annotations.SessionContext;
import org.jaxygen.annotations.Validable;
import org.jaxygen.converters.ConvertersFactory;
import org.jaxygen.converters.RequestConverter;
import org.jaxygen.converters.ResponseConverter;
import org.jaxygen.converters.exceptions.SerializationError;
import org.jaxygen.converters.json.JsonHRResponseConverter;
import org.jaxygen.converters.json.JsonMultipartRequestConverter;
import org.jaxygen.converters.json.JsonRequestConverter;
import org.jaxygen.converters.json.JsonResponseConverter;
import org.jaxygen.converters.prop2Json.Prop2JSONConverter;
import org.jaxygen.converters.properties.PropertiesToBeanConverter;
import org.jaxygen.converters.sjo.SJORRequestConverter;
import org.jaxygen.converters.sjo.SJOResponseConverter;
import org.jaxygen.converters.xml.XMLResponseConverter;
import org.jaxygen.dto.Downloadable;
import org.jaxygen.dto.ExceptionResponse;
import org.jaxygen.dto.Response;
import org.jaxygen.exceptions.InvalidPropertyFormat;
import org.jaxygen.exceptions.ParametersError;
import org.jaxygen.http.HttpRequestParams;
import org.jaxygen.http.HttpRequestParser;
import org.jaxygen.objectsbuilder.ObjectBuilder;
import org.jaxygen.objectsbuilder.ObjectBuilderFactory;
import org.jaxygen.propertyinjector.PropertyInjector;
import org.jaxygen.propertyinjector.ValueProvider;
import org.jaxygen.propertyinjector.exceptions.PropertyEnhancementException;
import org.jaxygen.security.SecurityProfile;
import org.jaxygen.security.annotations.Secured;
import org.jaxygen.security.annotations.SecurityContext;
import org.jaxygen.security.exceptions.NotAlowed;
import org.jaxygen.util.BeanUtil;

public class ServiceInvoker extends HttpServlet {

    private static final long serialVersionUID = 566338505269576162L;
    private static final Logger log = Logger.getLogger(ServiceInvoker.class.getCanonicalName());
    public static final String SERVICE_PATH = "servicePath";
    private String beensPath = null;

    static {
        // Register default converters
        ConvertersFactory.registerRequestConverter(new Prop2JSONConverter());
        ConvertersFactory.registerRequestConverter(new PropertiesToBeanConverter());
        ConvertersFactory.registerResponseConverter(new JsonResponseConverter());
        ConvertersFactory.registerRequestConverter(new JsonMultipartRequestConverter());
        ConvertersFactory.registerRequestConverter(new JsonRequestConverter());
        ConvertersFactory.registerRequestConverter(new SJORRequestConverter());
        ConvertersFactory.registerResponseConverter(new SJOResponseConverter());
        ConvertersFactory.registerResponseConverter(new XMLResponseConverter());
        ConvertersFactory.registerResponseConverter(new JsonHRResponseConverter());
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        beensPath = config.getInitParameter(SERVICE_PATH);
    }

    private String buildClassName(final String servicesRoot, final String className) {
        String fullClassName = className;
        if (!servicesRoot.isEmpty()) {
            fullClassName = servicesRoot + "." + className;
        }
        return fullClassName;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setCharacterEncoding("UTF-8");
        HttpRequestParams params = null;
        try {
            params = new HttpRequestParser(request);
        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            throwError(response.getOutputStream(), new JsonResponseConverter(), "Could not parse properties", ex);
        }
        System.out.println("beensPath: " + beensPath);
        if (beensPath == null) {
            beensPath = getServletContext().getInitParameter(SERVICE_PATH);
            System.out.println("beensPath: " + beensPath);
        }
        final String resourcePath = request.getPathInfo();
        final String queryString = request.getQueryString();

        final String inputFormat = params.getAsString("inputType", 0, 32, PropertiesToBeanConverter.NAME);
        final String outputFormat = params.getAsString("outputType", 0, 32, JsonResponseConverter.NAME);

        System.out.println("resourcePath: " + resourcePath);
        System.out.println("queryString: " + queryString);
        System.out.println("inputFormat: " + inputFormat);
        System.out.println("outputFormat: " + outputFormat);
        System.out.println("!!!!!!!!!!!!!!!!!");
        System.out.println("parameters------------: ");
        for (Map.Entry<String, String> e : params.getParameters().entrySet()) {
            System.out.println("parameter: " + e.getKey() + " : " + e.getValue());
        }
        System.out.println("parameters------------: ");
        String query = "";
        if (queryString != null) {
            query = URLDecoder.decode(queryString, "UTF-8");
        }
    }

    public void doGet(String resourcePath, String outputFormat, String inputFormat, OutputStream responseOutputStream, HttpRequestParams params, String beenPathBlaBla) throws IOException {

        if (beensPath == null) {
            beensPath = beenPathBlaBla;
        }
        ResponseConverter responseConverter = ConvertersFactory.getResponseConverter(outputFormat);
        if (responseConverter == null) {
            responseConverter = new JsonResponseConverter();
        }

//        log("Requesting resource" + resourcePath);
        String[] chunks = resourcePath.split("/");

        if (chunks.length < 2) {
            Logger.getLogger(ServiceInvoker.class.getName()).log(Level.SEVERE, "Invalid request, must be in format class/method");
            throw new RuntimeException("Invalid '" + resourcePath + "' request, must be in format class/method");
        }
        final String methodName = chunks[chunks.length - 1];
        final String className = buildClassName(beensPath, chunks[chunks.length - 2]);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        Method[] methods;
        try {
            Class clazz = cl.loadClass(className);
            if (clazz != null) {
                boolean methodFound = false;
                methods = clazz.getMethods();
                for (Method m : methods) {
                    if (m.isAnnotationPresent(NetAPI.class)
                            && m.getName().equals(methodName)) {
                        try {
                            methodFound = true;
//                            checkMethodAllowed(session, clazz.getCanonicalName(), m);
                            final Class<?>[] parameterTypes = m.getParameterTypes();
                            Object[] parameters = parseParameters(parameterTypes, inputFormat, params, "foobarQuery");
                            ObjectBuilder ob = ObjectBuilderFactory.instance();
                            Object been = ob.create(clazz);
                            validate(parameters);
                            try {
//                                extendDTO(parameters, request);
//                                injectSecutityProfile(been, session);
                                Class<?> responseType = m.getReturnType();
                                Object o = m.invoke(been, parameters);
                                if (o instanceof Downloadable) {
//                                    FileDeliveryHandler.postFile(request, response, (Downloadable) o);
                                } else {
                                    if (o instanceof SecurityProfile) {
//                                        SecurityProfileDTO profileDto = new SecurityProfileDTO();
//                                        SecurityProfile profile = (SecurityProfile) o;
//                                        profileDto.setGroups(profile.getUserGroups());
//                                        profileDto.setAllowedMethods(profile.getAllowedMethodDescriptors());
//                                        response.setCharacterEncoding("UTF-8");
//                                        sendSerializedResponse(SecurityProfileDTO.class, profileDto, responseConverter, response);
                                    } else {
//                                        response.setCharacterEncoding("UTF-8");
                                        sendSerializedResponse(responseType, o, responseConverter, responseOutputStream);
                                    }
                                }
//                                if (m.isAnnotationPresent(LoginMethod.class)) {
//                                    boolean profileConfigured = updateSessionSecurityProfile(been, session);
//                                    if (!profileConfigured && !(o instanceof SecurityProfile)) {
//                                        throwError(response, responseConverter, "Incompatible interface", "Method " + clazz + "." + methodName + " is annotated with @Login but does not return " + SecurityProfile.class.getCanonicalName());
//                                    }
//                                    if (o instanceof SecurityProfile) {
//                                        attachSecurityContextToSession(session, (SecurityProfile) o);
//                                    }
//                                }
//                                if (m.isAnnotationPresent(LogoutMethod.class)) {
//                                    detachSecurityContext(session);
//                                }
                            } catch (InvocationTargetException ex) {
                                throwError(responseOutputStream, responseConverter, "Call to bean failed : " + ex.getTargetException().getMessage(), ex.getTargetException());
                            } catch (Exception ex) {
                                throwError(responseOutputStream, responseConverter, "Call to bean failed : " + ex.getMessage(), ex);
                            }
                        } catch (Exception ex) {
                            throwError(responseOutputStream, responseConverter, "Cann not intanitiate class " + clazz.getCanonicalName(), ex);
                        }

                    }
                }
                if (!methodFound) {
                    throwError(responseOutputStream, responseConverter, "InvalidRequest", "Method " + className + "." + methodName + " not found");
                }
            } else {
                throwError(responseOutputStream, responseConverter, "InternalError", "Class '" + className + "' not fount");
            }

        } catch (ClassNotFoundException ex) {
            throwError(responseOutputStream, responseConverter, "Class '" + className + "' not fount", ex);

        } finally {
//            if (params != null) {
//                params.dispose();
//            }
        }

    }

    private void extendDTO(Object[] objects, final HttpServletRequest request) throws PropertyEnhancementException {
        PropertyInjector.bind(objects,
                ValueProvider.on(ClientIp.class).provide(() -> {
                    return getPublicIpAddress(request);
                }),
                ValueProvider.on(RequestURL.class).provide(() -> {
                    return request.getRequestURL().toString();
                }));
    }

    private Object[] parseParameters(final Class<?>[] parameterTypes, final String inputFormat, HttpRequestParams params, String query) throws ParametersError {
        Object parameters[] = new Object[parameterTypes.length];
        int i = 0;
        for (Class<?> p : parameterTypes) {
            try {
                RequestConverter converter = ConvertersFactory.getRequestConverter(inputFormat);
                if (converter != null) {
                    parameters[i] = converter.deserialise(params, p);
                } else {
                    log.log(Level.WARNING, "Could not find converter for name ''{0}''", inputFormat);
                }
            } catch (Exception ex) {
                throw new ParametersError("Cann not parse parameters for parameters class " + p.getCanonicalName(), ex);
            }
            i++;
        }
        return parameters;
    }

    private static void callSetter(Field f, Object been, Object sp) throws SecurityException, IllegalArgumentException, IllegalAccessException {
        boolean accessibility = f.isAccessible();
        f.setAccessible(true);
        f.set(been, sp);
        f.setAccessible(accessibility);
    }

    private static Object callGetter(Field f, Object been) throws SecurityException, IllegalArgumentException, IllegalAccessException {
        boolean accessibility = f.isAccessible();
        f.setAccessible(true);
        Object sp = f.get(been);
        f.setAccessible(accessibility);
        return sp;
    }

    private void throwError(OutputStream responseOutputStream, ResponseConverter converter, String string, Throwable ex) throws IOException {
        log.log(Level.SEVERE, string, ex);
//        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        ExceptionResponse resp = new ExceptionResponse(ex, string);
        try {
            converter.serialize(resp, responseOutputStream);
        } catch (SerializationError ex1) {
            log.log(Level.SEVERE, "Server was unable to inform peer about exception", ex);
        }
    }

    private void throwError(OutputStream responseOutputStream, ResponseConverter converter, final String codeName, String message) throws IOException {
        log.log(Level.SEVERE, message);
        ExceptionResponse resp = new ExceptionResponse(codeName, message);
        try {
//            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            converter.serialize(resp, responseOutputStream);
        } catch (SerializationError ex1) {
            log.log(Level.SEVERE, "Server was unable to inform peer about exception", ex1);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        System.out.println("POST");
        doGet(request, response);
    }

    private void attachSecurityContextToSession(HttpSession session, SecurityProfile securityProvider) {
        session.setAttribute(SecurityProfile.class.getCanonicalName(), securityProvider);
    }

    private void checkMethodAllowed(HttpSession session, final String clazz, Method method) throws NotAlowed {
        SecurityProfile sp = (SecurityProfile) session.getAttribute(SecurityProfile.class.getCanonicalName());
        if (method.isAnnotationPresent(Secured.class) && (sp == null || sp.isAllowed(clazz, method.getName()) == null)) {
            throw new NotAlowed(clazz, method.getName());
        }
    }

    private void detachSecurityContext(HttpSession session) {
        session.setAttribute(SecurityProfile.class.getCanonicalName(), null);
    }

    //Inject security profile attribute if been contains field annotated by SecurityContext attribute
    private void injectSecutityProfile(Object been, HttpSession session) throws IllegalArgumentException, IllegalAccessException {
        for (Field f : been.getClass().getDeclaredFields()) {
            SecurityProfile sp = (SecurityProfile) session.getAttribute(SecurityProfile.class.getCanonicalName());
            {
                SecurityContext sc = f.getAnnotation(SecurityContext.class);
                if (sc != null) {
                    callSetter(f, been, sp);
                }
            }
            {
                SessionContext sc = f.getAnnotation(SessionContext.class);
                if (sc != null) {
                    callSetter(f, been, session);
                }
            }
        }
    }

    private boolean updateSessionSecurityProfile(Object been, HttpSession session) throws IllegalArgumentException, IllegalAccessException {
        SecurityProfile sp = (SecurityProfile) session.getAttribute(SecurityProfile.class.getCanonicalName());
        boolean sessionContextUpdated = false;
        SecurityProfile newSp = sp;
        for (Field f : been.getClass().getDeclaredFields()) {
            {
                SecurityContext sc = f.getAnnotation(SecurityContext.class);
                if (sc != null) {
                    newSp = (SecurityProfile) callGetter(f, been);
                    sessionContextUpdated = true;
                }
            }
        }
        if (sp != newSp) {
            session.setAttribute(SecurityProfile.class.getCanonicalName(), newSp);
        }
        return sessionContextUpdated;
    }

    private void validate(Object[] parameters) throws IllegalArgumentException, IllegalAccessException, InvocationTargetException, InvalidPropertyFormat {
        for (Object o : parameters) {
            if (o.getClass().isAnnotationPresent(Validable.class)) {
                BeanUtil.validateBean(o);
            }
        }
    }

    private void sendSerializedResponse(Class<?> responseClass, Object o, ResponseConverter converter, HttpServletResponse response) throws SerializationError, IOException, ServletException {
        Response responseWraper = new Response(responseClass, o);
        converter.serialize(responseWraper, response.getOutputStream());
    }

    private void sendSerializedResponse(Class<?> responseClass, Object o, ResponseConverter converter, OutputStream outputStream) throws SerializationError, IOException, ServletException {
        Response responseWraper = new Response(responseClass, o);
        converter.serialize(responseWraper, outputStream);
    }

    private String getPublicIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("x-forwarded-for");
        if (ipAddress == null) {
            ipAddress = request.getHeader("X_FORWARDED_FOR");
            if (ipAddress == null) {
                ipAddress = request.getRemoteAddr();
            }
        }
        return ipAddress;
    }
}
