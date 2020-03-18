---
layout: post
title:  openshift中ingress自动转换route
categories: [openshift]
description: openshift中ingress自动转换route
keywords: openshift,ingress,route
---

### 1. 源头
在openshift中的route添加域名证书，必须要把证书及私钥写进route yaml的字段中，如下：

```yaml
apiVersion: v1
kind: Route
metadata:
  name: route-edge-secured 
spec:
  host: www.example.com
  to:
    kind: Service
    name: service-name 
  tls:
    termination: edge            
    key: |-                      
      -----BEGIN PRIVATE KEY-----
      [...]
      -----END PRIVATE KEY-----
    certificate: |-              
      -----BEGIN CERTIFICATE-----
      [...]
      -----END CERTIFICATE-----
    caCertificate: |-            
      -----BEGIN CERTIFICATE-----
      [...]
      -----END CERTIFICATE-----
```

这样在用openshift的template时，要把证书信息作为参数传进去。

但是在原生kubernetes中的ingress资源，可以支持传入一个secret，该secret中保存tls.crt、tls.key证书信息，然后将secret写进ingress的参数即可，如下：
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: testsecret-tls
  namespace: default
data:
  tls.crt: base64 encoded cert
  tls.key: base64 encoded key
type: kubernetes.io/tls
```
secret的type为`kuberntes.io/tls`
```yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: tls-example-ingress
spec:
  tls:
  - hosts:
    - sslexample.foo.com
    secretName: testsecret-tls
  rules:
    - host: sslexample.foo.com
      http:
        paths:
        - path: /
          backend:
            serviceName: service1
            servicePort: 80
```
在ingress中引用secret的名称，即可将证书与该域名绑定。

### 2. 解决
在openshift官网中，发现可以将ingress资源转为route：

https://docs.openshift.com/container-platform/3.11/architecture/networking/routes.html#architecture-routes-support-for-ingress

The Kubernetes ingress object is a configuration object determining how inbound connections reach internal services. OpenShift Container Platform has support for these objects using a ingress controller configuration file.

This controller watches ingress objects and creates one or more routes to satisfy the conditions of the ingress object. The controller is also responsible for keeping the ingress object and generated route objects synchronized. This includes giving generated routes permissions on the secrets associated with the ingress object.

openshift通过使用ingress控制器可以支持将ingress资源转为route。

那么，可以使用这个方法，在openshift创建ingress资源，传入secret，来自动生成带证书的route。

官网有一个例子：
```yaml
kind: Ingress
apiVersion: extensions/v1beta1
metadata:
  name: test
spec:
  rules:
  - host: test.com
    http:
     paths:
     - path: /test
       backend:
        serviceName: test-1
        servicePort: 80
```
创建完ingress资源之后，会自动转为route：
```yaml
kind: Route
apiVersion: route.openshift.io/v1
metadata:
  name: test-a34th 
  ownerReferences:
  - apiVersion: extensions/v1beta1
    kind: Ingress
    name: test
    controller: true
spec:
  host: test.com
  path: /test
  to:
    name: test-1
  port:
     targetPort: 80
```

### 3. 问题

但是，使用官方例子，在openshift创建完ingress之后，查看route，并未生成route。以为是要装插件，或有什么使用条件。之后，就是一顿查，通过搜寻各种网站，翻看官网，并未发现其它任何资料。

然后，看到上面说是通过controller来进行自动转换的。所以，决定把openshift源码clone下来，研究下ingress controller是怎么进行转换的。

### 4. 分析

克隆下来openshift源码（https://github.com/openshift/origin ）,切换到release-3.11分支，找到ingress controller逻辑，如下：

`origin/pkg/route/controller/ingress/ingress.go`

```golang
var creates, updates []*routev1.Route
	for _, rule := range ingress.Spec.Rules {
	    // ingress的rule中没有http字段不会转换
		if rule.HTTP == nil {
			continue
		}
		// ingress的rule中没有host字段不会转换
		if len(rule.Host) == 0 {
			continue
		}
		for _, path := range rule.HTTP.Paths {
		    // http列表字段中没有serviceName，不会转换
			if len(path.Backend.ServiceName) == 0 {
				continue
			}

			var existing *routev1.Route
			// 查询是否存在已有route跟ingress host及path相同
			old, existing = splitForPathAndHost(old, rule.Host, path.Path)
			if existing == nil {
			    // 不存在已有route，新建ingress转换的route资源
				if r := newRouteForIngress(ingress, &rule, &path, c.secretLister, c.serviceLister); r != nil {
					creates = append(creates, r)
				}
				continue
			}

			if routeMatchesIngress(existing, ingress, &rule, &path, c.secretLister, c.serviceLister) {
				continue
			}

			if r := newRouteForIngress(ingress, &rule, &path, c.secretLister, c.serviceLister); r != nil {
				// merge the relevant spec pieces
				preserveRouteAttributesFromExisting(r, existing)
				updates = append(updates, r)
			} else {
				// the route cannot be fully calculated, delete it
				old = append(old, existing)
			}
		}
	}
```
上述就是ingress转换route的逻辑，如果ingress没有http，host，以及path中没有serviceName，都不会转换为route。

而且，如果已生成了route，还会根据ingress的改变，自动改变对应route资源。

下面是根据ingress生成route的逻辑：
```golang
func newRouteForIngress(
	ingress *extensionsv1beta1.Ingress,
	rule *extensionsv1beta1.IngressRule,
	path *extensionsv1beta1.HTTPIngressPath,
	secretLister corelisters.SecretLister,
	serviceLister corelisters.ServiceLister,
) *routev1.Route {
	var tlsConfig *routev1.TLSConfig
	// ingress是否引用secret，来传入证书
	if name, ok := referencesSecret(ingress, rule.Host); ok {
		secret, err := secretLister.Secrets(ingress.Namespace).Get(name)
		// 未找到secret，不会创建route
		if err != nil {
			// secret doesn't exist yet, wait
			return nil
		}
		// secret类型不是kubernetes.io/tls，不会创建route
		if secret.Type != v1.SecretTypeTLS {
			// secret is the wrong type
			return nil
		}
		// secret数据中没有tls.crt，不会创建route
		if _, ok := secret.Data[v1.TLSCertKey]; !ok {
			return nil
		}
		// secret数据中没有tls.key，不会创建route
		if _, ok := secret.Data[v1.TLSPrivateKeyKey]; !ok {
			return nil
		}
		tlsConfig = &routev1.TLSConfig{
			Termination: routev1.TLSTerminationEdge,
			Certificate: string(secret.Data[v1.TLSCertKey]),
			Key:         string(secret.Data[v1.TLSPrivateKeyKey]),
			InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
		}
	}
    // 在namespace中查找对应service存在的port，逻辑见下
	targetPort := targetPortForService(ingress.Namespace, path, serviceLister)
	// 未找到service对应port，不会创建route
	if targetPort == nil {
		// no valid target port
		return nil
	}

	t := true
	return &routev1.Route{
	    ...	
	}
}
```
上述逻辑可以看到，如果在openshift中未找到ingress字段中secret，以及secret的类型不匹配、数据不存在， 都不会创建route。

还会查找ingress path中对应的service以及port是否存在，如果不存在，也不会创建route：
```golang
func targetPortForService(namespace string, path *extensionsv1beta1.HTTPIngressPath, serviceLister corelisters.ServiceLister) *intstr.IntOrString {
	service, err := serviceLister.Services(namespace).Get(path.Backend.ServiceName)
	// 未找到service资源，不会创建route
	if err != nil {
		// service doesn't exist yet, wait
		return nil
	}
	// service资源中的端口要跟ingress中要一致，否则不会创建route
	if path.Backend.ServicePort.Type == intstr.String {
		expect := path.Backend.ServicePort.StrVal
		for _, port := range service.Spec.Ports {
			if port.Name == expect {
				return &port.TargetPort
			}
		}
	} else {
		for _, port := range service.Spec.Ports {
			expect := path.Backend.ServicePort.IntVal
			if port.Port == expect {
				return &port.TargetPort
			}
		}
	}
	return nil
}
```

### 5. 结论

综上，在ingress转换route的过程中，有一些限制条件：
1. ingress规则中必须要有host、http以及serviceName；
3. ingress字段backend中的serviceName，必须在openshift存在对应service资源，且servicePort也要跟service资源中的port一致；
2. ingress中如有tls secret，则secret资源在openshift必须存在，且secert类型为`kubernetes.io/tls`，数据中要包含tls.crt及tls.key。

而且，直接修改生成的route，不会生效。但是可以修改ingress，会自动更新对应route。有一点要注意：**`如果修改ingress，不满足上述限制条件，会自动删除对应route`**。
