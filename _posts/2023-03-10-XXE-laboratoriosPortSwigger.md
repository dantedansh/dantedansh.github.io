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

Ahora lo que haremos será 