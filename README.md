# How to run multiple instances of Nemhandel eDelivery Oxalis on the same tomcat

## Introduction

In some situations it is required to run several instances of [Oxalis NemHandel Reference Implementations](https://rep.erst.dk/git/openebusiness/nemhandeledelivery) on the same Tomcat, e.g. TEST and PROD instance or PROD Nemhandel and PROD Peppol. In general, it is not recommended, as Tomcat starts to serve requests only after ALL instances are initialized, also as sharing memory between different instances with different workload and requirements is also not good.

## Issue

When multiple instances of Oxalis are running in the same default Tomcat 9 configuration, next errors can occur:

- **javax.security.auth.callback.UnsupportedCallbackException**
```
        org.apache.cxf.binding.soap.SoapFault: A security error was encountered when verifying the message
                at org.apache.cxf.ws.security.wss4j.WSS4JUtils.createSoapFault(WSS4JUtils.java:240)
                at org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor.handleMessageInternal(WSS4JInInterceptor.java:382)
                at org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor.handleMessage(WSS4JInInterceptor.java:213)
                at org.apache.cxf.ws.security.wss4j.PolicyBasedWSS4JInInterceptor.handleMessage(PolicyBasedWSS4JInInterceptor.java:123)
                at org.apache.cxf.ws.security.wss4j.PolicyBasedWSS4JInInterceptor.handleMessage(PolicyBasedWSS4JInInterceptor.java:76)
                at org.apache.cxf.phase.PhaseInterceptorChain.doIntercept(PhaseInterceptorChain.java:307)
                at org.apache.cxf.transport.MultipleEndpointObserver.onMessage(MultipleEndpointObserver.java:98)
                at org.apache.cxf.transport.http.AbstractHTTPDestination.invoke(AbstractHTTPDestination.java:265)
                at org.apache.cxf.transport.servlet.ServletController.invokeDestination(ServletController.java:234)
                at org.apache.cxf.transport.servlet.ServletController.invoke(ServletController.java:208)
                at org.apache.cxf.transport.servlet.ServletController.invoke(ServletController.java:160)
                at org.apache.cxf.transport.servlet.CXFNonSpringServlet.invoke(CXFNonSpringServlet.java:225)
                at org.apache.cxf.transport.servlet.AbstractHTTPServlet.handleRequest(AbstractHTTPServlet.java:304)
                at org.apache.cxf.transport.servlet.AbstractHTTPServlet.doPost(AbstractHTTPServlet.java:217)
                at javax.servlet.http.HttpServlet.service(HttpServlet.java:555)
                at org.apache.cxf.transport.servlet.AbstractHTTPServlet.service(AbstractHTTPServlet.java:279)
                at com.google.inject.servlet.ServletDefinition.doServiceImpl(ServletDefinition.java:290)
                at com.google.inject.servlet.ServletDefinition.doService(ServletDefinition.java:280)
                at com.google.inject.servlet.ServletDefinition.service(ServletDefinition.java:184)
                at com.google.inject.servlet.ManagedServletPipeline.service(ManagedServletPipeline.java:89)
                at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:85)
                at io.opentracing.contrib.web.servlet.filter.TracingFilter.doFilter(TracingFilter.java:189)
                at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
                at com.google.inject.persist.PersistFilter.doFilter(PersistFilter.java:94)
                at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
                at com.google.inject.servlet.ManagedFilterPipeline.dispatch(ManagedFilterPipeline.java:121)
                at com.google.inject.servlet.GuiceFilter.doFilter(GuiceFilter.java:133)
                at network.oxalis.dist.war.WarGuiceFilter.doFilter(WarGuiceFilter.java:21)
                at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:178)
                at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:153)
                at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:168)
                at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:90)
                at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:481)
                at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:130)
                at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:93)
                at org.apache.catalina.valves.AbstractAccessLogValve.invoke(AbstractAccessLogValve.java:670)
                at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:74)
                at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:343)
                at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:390)
                at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:63)
                at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:926)
                at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1790)
                at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:52)
                at org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1191)
                at org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:659)
                at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
                at java.lang.Thread.run(Thread.java:750)
        Caused by: org.apache.wss4j.common.ext.WSSecurityException: javax.xml.crypto.dsig.TransformException: javax.security.auth.callback.UnsupportedCallbackException: Unsupported callback
Original Exception was javax.xml.crypto.dsig.XMLSignatureException: javax.xml.crypto.dsig.TransformException: javax.security.auth.callback.UnsupportedCallbackException: Unsupported callback
                at org.apache.wss4j.dom.processor.SignatureProcessor.verifyXMLSignature(SignatureProcessor.java:408)
                at org.apache.wss4j.dom.processor.SignatureProcessor.handleToken(SignatureProcessor.java:230)
                at org.apache.wss4j.dom.engine.WSSecurityEngine.processSecurityHeader(WSSecurityEngine.java:340)
                at org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor.handleMessageInternal(WSS4JInInterceptor.java:326)
                ... 45 more
        Caused by: javax.xml.crypto.dsig.XMLSignatureException: javax.xml.crypto.dsig.TransformException: javax.security.auth.callback.UnsupportedCallbackException: Unsupported callback
                at org.apache.jcp.xml.dsig.internal.dom.DOMReference.transform(DOMReference.java:541)
                at org.apache.jcp.xml.dsig.internal.dom.DOMReference.validate(DOMReference.java:380)
                at org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignature.validate(DOMXMLSignature.java:274)
                at org.apache.wss4j.dom.processor.SignatureProcessor.verifyXMLSignature(SignatureProcessor.java:381)
                ... 48 more
        Caused by: javax.xml.crypto.dsig.TransformException: javax.security.auth.callback.UnsupportedCallbackException: Unsupported callback
                at org.apache.wss4j.dom.transform.AttachmentContentSignatureTransform.attachmentRequestCallback(AttachmentContentSignatureTransform.java:137)
                at org.apache.wss4j.dom.transform.AttachmentContentSignatureTransform.transform(AttachmentContentSignatureTransform.java:120)
                at org.apache.jcp.xml.dsig.internal.dom.DOMTransform.transform(DOMTransform.java:166)
                at org.apache.jcp.xml.dsig.internal.dom.DOMReference.transform(DOMReference.java:451)
                ... 51 more
        Caused by: javax.security.auth.callback.UnsupportedCallbackException: Unsupported callback
                at org.apache.cxf.ws.security.wss4j.AttachmentCallbackHandler.handle(AttachmentCallbackHandler.java:113)
                at org.apache.wss4j.dom.transform.AttachmentContentSignatureTransform.attachmentRequestCallback(AttachmentContentSignatureTransform.java:135)
                ... 54 more
```

- **java.security.InvalidAlgorithmParameterException: Expected AttachmentTransformParameterSpec**
(in case of NemHandel Reference Implementation sends document from second loaded Oxalis instance):

```
dk.erst.oxalis.as4.handlers.OutboundException: Error while transmitting request
        at dk.erst.oxalis.as4.util.OxalisDocumentSender.send(OxalisDocumentSender.java:249)
        at dk.erst.oxalis.as4.handlers.SendSbdHandler.handle(SendSbdHandler.java:84)
        at dk.erst.oxalis.as4.rest.resources.OutboxResource.sendStandardBusinessDocument(OutboxResource.java:179)
        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
        at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
        at java.lang.reflect.Method.invoke(Method.java:498)
        at org.jboss.resteasy.core.MethodInjectorImpl.invoke(MethodInjectorImpl.java:170)
        at org.jboss.resteasy.core.MethodInjectorImpl.invoke(MethodInjectorImpl.java:130)
        at org.jboss.resteasy.core.ResourceMethodInvoker.internalInvokeOnTarget(ResourceMethodInvoker.java:660)
        at org.jboss.resteasy.core.ResourceMethodInvoker.invokeOnTargetAfterFilter(ResourceMethodInvoker.java:524)
        at org.jboss.resteasy.core.ResourceMethodInvoker.lambda$invokeOnTarget$2(ResourceMethodInvoker.java:474)
        at org.jboss.resteasy.core.interception.jaxrs.PreMatchContainerRequestContext.filter(PreMatchContainerRequestContext.java:364)
        at org.jboss.resteasy.core.ResourceMethodInvoker.invokeOnTarget(ResourceMethodInvoker.java:476)
        at org.jboss.resteasy.core.ResourceMethodInvoker.invoke(ResourceMethodInvoker.java:434)
        at org.jboss.resteasy.core.ResourceMethodInvoker.invoke(ResourceMethodInvoker.java:408)
        at org.jboss.resteasy.core.ResourceMethodInvoker.invoke(ResourceMethodInvoker.java:69)
        at org.jboss.resteasy.core.SynchronousDispatcher.invoke(SynchronousDispatcher.java:492)
        at org.jboss.resteasy.core.SynchronousDispatcher.lambda$invoke$4(SynchronousDispatcher.java:261)
        at org.jboss.resteasy.core.SynchronousDispatcher.lambda$preprocess$0(SynchronousDispatcher.java:161)
        at org.jboss.resteasy.core.interception.jaxrs.PreMatchContainerRequestContext.filter(PreMatchContainerRequestContext.java:364)
        at org.jboss.resteasy.core.SynchronousDispatcher.preprocess(SynchronousDispatcher.java:164)
        at org.jboss.resteasy.core.SynchronousDispatcher.invoke(SynchronousDispatcher.java:247)
        at org.jboss.resteasy.plugins.server.servlet.ServletContainerDispatcher.service(ServletContainerDispatcher.java:249)
        at org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher.service(HttpServletDispatcher.java:60)
        at org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher.service(HttpServletDispatcher.java:55)
        at javax.servlet.http.HttpServlet.service(HttpServlet.java:623)
        at com.google.inject.servlet.ServletDefinition.doServiceImpl(ServletDefinition.java:290)
        at com.google.inject.servlet.ServletDefinition.doService(ServletDefinition.java:280)
        at com.google.inject.servlet.ServletDefinition.service(ServletDefinition.java:184)
        at com.google.inject.servlet.ManagedServletPipeline.service(ManagedServletPipeline.java:89)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:85)
        at io.opentracing.contrib.web.servlet.filter.TracingFilter.doFilter(TracingFilter.java:189)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
        at dk.erst.oxalis.as4.async.ExecutorServiceLifecycleFilter.doFilter(ExecutorServiceLifecycleFilter.java:57)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
        at dk.erst.oxalis.as4.rest.RestFilter.doFilter(RestFilter.java:53)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
        at dk.erst.oxalis.as4.rest.security.SecurityFilter.doFilter(SecurityFilter.java:108)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
        at dk.erst.oxalis.as4.jdbc.JdbcFilter.doFilter(JdbcFilter.java:47)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
        at com.google.inject.persist.PersistFilter.doFilter(PersistFilter.java:94)
        at com.google.inject.servlet.FilterChainInvocation.doFilter(FilterChainInvocation.java:82)
        at com.google.inject.servlet.ManagedFilterPipeline.dispatch(ManagedFilterPipeline.java:121)
        at com.google.inject.servlet.GuiceFilter.doFilter(GuiceFilter.java:133)
        at network.oxalis.dist.war.WarGuiceFilter.doFilter(WarGuiceFilter.java:21)
        at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:178)
        at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:153)
        at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:168)
        at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:90)
        at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:481)
        at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:130)
        at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:93)
        at org.apache.catalina.valves.AbstractAccessLogValve.invoke(AbstractAccessLogValve.java:670)
        at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:74)
        at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:343)
        at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:390)
        at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:63)
        at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:926)
        at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1790)
        at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:52)
        at org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1191)
        at org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:659)
        at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
        at java.lang.Thread.run(Thread.java:750)
Caused by: network.oxalis.as4.lang.OxalisAs4TransmissionException: Failed to send message
        at network.oxalis.as4.outbound.As4MessageSender.invoke(As4MessageSender.java:108)
        at network.oxalis.as4.outbound.As4MessageSender.send(As4MessageSender.java:89)
        at network.oxalis.as4.outbound.As4MessageSenderFacade.send(As4MessageSenderFacade.java:20)
        at network.oxalis.api.outbound.MessageSender.send(MessageSender.java:59)
        at network.oxalis.outbound.transmission.DefaultTransmitter.perform(DefaultTransmitter.java:149)
        at network.oxalis.outbound.transmission.DefaultTransmitter.transmit(DefaultTransmitter.java:106)
        at dk.erst.oxalis.as4.util.OxalisDocumentSender.send(OxalisDocumentSender.java:217)
        ... 65 common frames omitted
Caused by: javax.xml.ws.soap.SOAPFaultException: No message with ID "noXMLSig" found in resource bundle "org/apache/xml/security/resource/xmlsecurity". Original Exception was a org.apache.wss4j.common.ext.WSSecurityException and message Expected AttachmentTransformParameterSpec
        at org.apache.cxf.jaxws.DispatchImpl.mapException(DispatchImpl.java:285)
        at org.apache.cxf.jaxws.DispatchImpl.invoke(DispatchImpl.java:330)
        at org.apache.cxf.jaxws.DispatchImpl.invoke(DispatchImpl.java:241)
        at network.oxalis.as4.outbound.As4MessageSender.invoke(As4MessageSender.java:105)
        ... 71 common frames omitted
Caused by: org.apache.cxf.interceptor.Fault: No message with ID "noXMLSig" found in resource bundle "org/apache/xml/security/resource/xmlsecurity". Original Exception was a org.apache.wss4j.common.ext.WSSecurityException and message Expected AttachmentTransformParameterSpec
        at org.apache.cxf.ws.security.wss4j.policyhandlers.AsymmetricBindingHandler.doSignBeforeEncrypt(AsymmetricBindingHandler.java:258)
        at org.apache.cxf.ws.security.wss4j.policyhandlers.AsymmetricBindingHandler.handleBinding(AsymmetricBindingHandler.java:126)
        at org.apache.cxf.ws.security.wss4j.PolicyBasedWSS4JOutInterceptor$PolicyBasedWSS4JOutInterceptorInternal.handleMessageInternal(PolicyBasedWSS4JOutInterceptor.java:186)
        at org.apache.cxf.ws.security.wss4j.PolicyBasedWSS4JOutInterceptor$PolicyBasedWSS4JOutInterceptorInternal.handleMessage(PolicyBasedWSS4JOutInterceptor.java:110)
        at org.apache.cxf.ws.security.wss4j.PolicyBasedWSS4JOutInterceptor$PolicyBasedWSS4JOutInterceptorInternal.handleMessage(PolicyBasedWSS4JOutInterceptor.java:97)
        at org.apache.cxf.phase.PhaseInterceptorChain.doIntercept(PhaseInterceptorChain.java:307)
        at org.apache.cxf.endpoint.ClientImpl.doInvoke(ClientImpl.java:528)
        at org.apache.cxf.endpoint.ClientImpl.invoke(ClientImpl.java:439)
        at org.apache.cxf.endpoint.ClientImpl.invoke(ClientImpl.java:354)
        at org.apache.cxf.endpoint.ClientImpl.invoke(ClientImpl.java:312)
        at org.apache.cxf.endpoint.ClientImpl.invokeWrapped(ClientImpl.java:347)
        at org.apache.cxf.jaxws.DispatchImpl.invoke(DispatchImpl.java:322)
        ... 73 common frames omitted
Caused by: org.apache.wss4j.common.ext.WSSecurityException: No message with ID "noXMLSig" found in resource bundle "org/apache/xml/security/resource/xmlsecurity". Original Exception was a org.apache.wss4j.common.ext.WSSecurityException and message Expected AttachmentTransformParameterSpec
        at org.apache.wss4j.dom.message.WSSecSignatureBase.addReferencesToSign(WSSecSignatureBase.java:221)
        at org.apache.wss4j.dom.message.WSSecSignature.addReferencesToSign(WSSecSignature.java:432)
        at org.apache.cxf.ws.security.wss4j.policyhandlers.AsymmetricBindingHandler.doSignature(AsymmetricBindingHandler.java:781)
        at org.apache.cxf.ws.security.wss4j.policyhandlers.AsymmetricBindingHandler.doSignBeforeEncrypt(AsymmetricBindingHandler.java:189)
        ... 84 common frames omitted
Caused by: org.apache.wss4j.common.ext.WSSecurityException: Expected AttachmentTransformParameterSpec
        at org.apache.wss4j.dom.message.WSSecSignatureBase.addAttachmentReferences(WSSecSignatureBase.java:304)
        at org.apache.wss4j.dom.message.WSSecSignatureBase.addReferencesToSign(WSSecSignatureBase.java:119)
        ... 87 common frames omitted
Caused by: java.security.InvalidAlgorithmParameterException: Expected AttachmentTransformParameterSpec
        at org.apache.wss4j.dom.transform.AttachmentContentSignatureTransform.init(AttachmentContentSignatureTransform.java:68)
        at org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignatureFactory.newTransform(DOMXMLSignatureFactory.java:321)
        at org.apache.wss4j.dom.message.WSSecSignatureBase.addAttachmentReferences(WSSecSignatureBase.java:293)
        ... 88 common frames omitted
```

## Reason

The reason was described in WSS4J issue https://issues.apache.org/jira/browse/WSS-660 by Philip Helger @phax - and suggested solution was to move wss4j.jar into Tomcat shared classloader.

It looks like the core reason is in the usage of java.security.Security addProvider()/removeProvider() - if it is executed on the same providers in different webapps, they compete with each other to install webapp-specific classloader classes into global providers. As a result, when 2 webapps call org.apache.wss4j.dom.engine.WSSConfig.init() during initialization, e.g. in the order oxalis1 and oxalis2, then oxalis2 "wins" and registers classes from its own specific classloader (e.g. webapps/oxalis2.war/WEB-INF/lib).

So when oxalis1 processes a request, it gets a mixture of instances of classes - loaded via global Security provider and direct own classloader, and Java considers same classes, loaded by different classloaders, as different classes, so checks like 

```
        if (!(params instanceof AttachmentTransformParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Expected AttachmentTransformParameterSpec");
        }
```
or 
```
            if (callback instanceof AttachmentRequestCallback) {
              ...
            } else if (callback instanceof AttachmentResultCallback) {
              ...
            } else if (callback instanceof AttachmentRemovalCallback) {
              ...
            } else {
                throw new UnsupportedCallbackException(callback, "Unsupported callback");
            }
```
fail with exceptions.

Maybe there is a way to avoid such a mixture of classloaders by reusing global provider instance in some way, but it requires changes in WSS4J code, so a solution with some Tomcat configuration is preferred at the moment.

## Solution analysis - Tomcat shared.loader

In general, Tomcat 9 supposes next hiearchy of classloaders (see [11. Classloading section of Apache Tomcat 9 Documentation](https://tomcat.apache.org/tomcat-9.0-doc/class-loader-howto.html):

![image](https://github.com/dladlk/oxalis-nemhandel-tomcat-multiple-instances/assets/41484081/456390fc-eadc-45cc-9917-a15b6e633a2b)

It gives possibility to solve the issue with multiple classloaders by moving some classes up the class loaders hierarchy, so they are considered by java as equal.

But each classloader can see only own classes or above its hieararchy, so e.g. classes in Shared classloader cannot load classes from Webapp2 classloader, so if we move e.g. all wss4j*.jars to shared.loader, or even only wss4j-ws-security-dom-2.4.1.jar (which contains AttachmentTransformParameterSpec) and wss4j-ws-security-common-2.4.1.jar (for AttachmentRequestCallback, AttachmentResultCallback and AttachmentRemovalCallback to be shared) - the application fails to start because these classes have a lot of dependencies on e.g. xmlsec-2.3.0.jar or slf4j-api-2.0.6.jar - so it becomes quite tedious process to pickup proper jars to share.

Extreme decision like moving ALL jars into shared.loader from webapp leads to loosing specific resources per webapp in WEB-INF/classes and is not acceptable, even supposing that Tomcat runs ONLY Oxalis instances.

Suggested solution - share only classes with MINIMAL dependencies on others, which could solve the problem, which at the moment of writing looks like those, used in WSS4J instanceof constructions, which fail Oxalis document exchange:


From **wss4j-ws-security-common-2.4.1.jar**, referenced in `org.apache.cxf.ws.security.wss4j.AttachmentCallbackHandler`:
- org.apache.wss4j.common.ext.AttachmentRequestCallback
- org.apache.wss4j.common.ext.AttachmentResultCallback
- org.apache.wss4j.common.ext.AttachmentRemovalCallback

From **wss4j-ws-security-dom-2.4.1.jar**, referenced in `org.apache.wss4j.dom.transform.AttachmentContentSignatureTransform`:
- org.apache.wss4j.dom.transform.AttachmentTransformParameterSpec

## Solution in short

2 new jars are created as a copies of original WSS4J jars, but all other classes are removed from them, and placed into Tomcat shared.loader:

- wss4j-ws-security-common-2.4.1-attachment-only.jar (4 classes - Attachment class is included too)
- wss4j-ws-security-dom-2.4.1-attachment-only.jar (1 class)



## Detailed steps

### Configure shared.loader

1. Activate shared.loader in Tomcat catalina.properties

By default, shared.loader is disabled in Tomcat 9. To enable it, modify **CATALINA_HOME/conf/catalina.properties** file and replace line 

```
shared.loader=
```

with something like

```
shared.loader="${catalina.home}/shared/lib","${catalina.home}/shared/lib/*.jar"
```

Actual folder can be different, it is just an old convention to use shared/lib for Tomcat coming from days when shared.loader was active by default.

2. Copy minimal jars into shared/lib

Create folder **CATALINA_HOME/shared/lib** and copy into it 2 jars (published into this repo or created by you):

- [wss4j-ws-security-common-2.4.1-attachment-only.jar](./dist/wss4j-ws-security-common-2.4.1-attachment-only.jar) (4 classes - Attachment class is included too)
- [wss4j-ws-security-dom-2.4.1-attachment-only.jar](./dist/wss4j-ws-security-dom-2.4.1-attachment-only.jar) (1 class)

3. Configure both webapps loader to try parent loader before own

Reason: to make solution easier to implement (to avoid deletion of moved classes to shared.loader from existing war), configure webapps loaders to prefer to use PARENT classloader first by adding to oxalis.conf context configuration next line:

```
	<Loader delegate="true"/>
```

See [Loader delegate attribute](https://tomcat.apache.org/tomcat-9.0-doc/config/loader.html#Common_Attributes)

So the context configuration at **CATALINA_HOME\conf\Catalina\localhost\oxalis.xml** looks something like:

```
<?xml version="1.0" encoding="UTF-8"?>
<Context docBase="oxalis.war">
	<Environment name="OXALIS_HOME" value="${catalina.base}/.oxalis" type="java.lang.String" override="false"/>
	<Resources className="org.apache.catalina.webresources.ExtractingRoot">
		<PostResources base="${catalina.base}\oxalis-as4" className="org.apache.catalina.webresources.DirResourceSet" webAppMount="/WEB-INF/lib"/>
	</Resources>
	<Loader delegate="true"/>
</Context>
```

4. Step 3. should be done for all Oxalis instances at Tomcat

Don't forget to add `<Loader delegate="true"/>` to all Oxalis instances on your Tomcat, not only oxalis.xml but e.g. oxalis2.xml, oxalis3.xml etc...

