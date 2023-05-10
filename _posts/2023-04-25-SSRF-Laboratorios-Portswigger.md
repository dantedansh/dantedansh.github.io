---
layout: single
title: SSRF - Laboratorios de PortSwigger
excerpt: "En este post, explicaremos ¿Que es? y como se realiza un ataque SSRF, server side request forgery."
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

# ¿Que es un ataque SSRF?

Un ataque SSRF(server side request forgery), Este ataque se da cuando una aplicación web, nos permite aprovecharnos de algun recurso para manipular y dirigir una petición maliciosa hacía el mismo servidor y obtener la resupesta.

Esto lo veremos más claro con el siguiente ejemplo, supongamos que tenemos nuestra maquina atacante, y tenemos conexión a un servidor web pero solo podemos acceder a este servidor web por el puerto 80(http):

![ssrf1](/assets/images/LabsSSRF/ssrf1.png)

como mencione en la imagen, tenemos acceso a el servidor web por el puerto 80, pero si intentamos acceder, o escanear los puertos que tiene abiertos internamente el servidor podremos ver que no nos va a dejar hacer algo.

Y esto es obviamente causado por algun firewall que hace que esos puertos no puedan salir de su red interna.

El unico que tiene conexión directa con esos puertos internos es el servidor victima.

<br>

Ahora supongamos un caso donde al servidor por el puerto 80 al cual tenemos acceso, contiene una función la cual es que incluye algo como un buscador dentro de la web, y lo que hace es mostrarnos el contenido de lo que le pidamos, en este caso debería mostrarnos la web de google:

![ssrf2](/assets/images/LabsSSRF/ssrf2.png)

Y la web nos interpretara ese contenido desde la función de el servidor victima, pero ahora algo que podriamos hacer, es que como vemos que el puerto 8080 el cual no tenemos acceso, supongamos que dicho puerto corre un servicio http, el cual contiene una pagina web que solo debería acceder las personas de la red interna.

Pero en este caso, como la función del buscador esta siendo ejecutada por el servidor victima, el cual tiene conexión con dichos puertos, lo que podemos hacer es lo siguiente:

![funcion](/assets/images/LabsSSRF/funcion.png)

Ahora podemos apreciar que en la función hemos puesto la URL apuntando hacía el puerto 8080 interno del servidor web, y como esta función si tiene acceso a dichos puertos entonces nos lo va a mostrar en la web que estamos viendo.

Como pusimos localhost en la url, quiere decir que se conectara a su misma maquia servidor que lo ejecuta pero por el puerto que le asignamos, en este caso el 8080, que contiene una web que no deberíamos poder ver en primer lugar pero hemos podido gracias a que usamos este ataque SSRF por medio de la función de busqueda.

Una vez entendido esto, pasemos a resolver el primer laboratorio.

<br>

# Laboratorio 1: SSRF básico contra el servidor local

Este laboratorio es un ejemplo muy basico pero que se logra entender la idea del SSRF, lo que nos piden es lo siguiente:

![lab1](/assets/images/LabsSSRF/lab1/lab1.png)

Nos dice que este laboratorio contiene una función de verificar existencias que obtiene datos de un sistema interno.

Y que debemos acceder a un panel de admin interno y eliminar a el usuario carlos.

Esto es parecido a los laboratorios de vulnerabilidades anteriores, así que primero iremos a la web y entraremos a un producto para encontrar la función de verificar existencias:

![func](/assets/images/LabsSSRF/lab1/funcion.png)

Como podemos ver, la función se encuentra aquí y al darle click nos toma datos de un sistema interno que registra los productos disponibles.

<br>

Así que lo que haremos ahora será interceptar una peticón de esa función usando BurpSuite, y veremos la siguiente petición:

![peticion](/assets/images/LabsSSRF/lab1/peticion.png)

Podemos observar que en esta petición tenemos una url, y vemos que al parecer esta url-encodeada, por lo que seleccionaremos la url, y al dar ctrl + shift + u hacemos el proceso inverso de url-encodear, osea que estamos quitando la codificacion url y veremos algo así:

![err](/assets/images/LabsSSRF/lab1/error.png)

Vemos que nos da el siguiente error, ya que debe estar url-encodeada, así que antes de volver a url-encodearla, podemos apreciar que hay una url la cual es:

`http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1`

Así que con esto podemos saber que por detras se esta llamando a la web de la url por el puerto 8080, y accediendo a un recurso dado por medio de los parametros, pero en este caso lo que haremos será acceder a el panel de admin que nos da el laboratorio como reto.

Así que cambiaremos la url de la petición por la que nos dice el laboratorio que se encuentra el panel admin:

`http://localhost/admin`

> Lo que estamos haciendo aqui es acceder a el mismo servidor de la maquina pero a la seccion de administrador, cosa que no podemos hacer directamente desde nuestra pc atacante pero si usando el sevidor que se mande a si mismo una consulta maliciosa como esta.

![admin](/assets/images/LabsSSRF/lab1/admin.png)

Podemos ver que nos ha cargado una pagina, la de administrador.

> No dejes espacios en la peticion interceptada ya que puede dar errores.

Ahora mandaremos esta peticion pero la que esta en el intercept para verla reflejada en nuestro navegador que se conecta con burp:

![intercept](/assets/images/LabsSSRF/lab1/intercept.png)

Y al tramitarla podemos ver que en la web del navegador se nos agrego esto:

![panel](/assets/images/LabsSSRF/lab1/panel.png)

Y al darle click a eliminar el usuario nos carga lo siguiente:

![no](/assets/images/LabsSSRF/lab1/no.png)

Vemos que nos dice que debemos hacer esto desde el panel de administrador y no nos deja hacerlo, pero si apreciamos arriba en la url vemos estos parametros:

**/admin/delete?username=carlos**

Por lo que simplemente haremos la peticion anterior de nuevo, pero esta vez agregando dichos parametros, y nos quedará así:

`http://localhost/admin/delete?username=carlos`

![delete](/assets/images/LabsSSRF/lab1/delete.png)

Y al tramitar esta petición habremos terminado el laboratorio:

![end](/assets/images/LabsSSRF/lab1/end.png)

<br>

# Laboratorio 2: SSRF básico contra otro sistema back-end

En este siguiente laboratorio veremos que nos piden realizar lo siguiente:

![lab2](/assets/images/LabsSSRF/lab2/lab2.png)

Nos dice que dentro de la red interna del servidor victima, hay otros equipos dentro de esa red interna pero que debemos encontrar el que tiene el puerto 8080 abierto y acceder a el y una vez accedamos debemos eliminar el usuario de carlos.

Por ejemplo:

![ips](/assets/images/LabsSSRF/lab2/ips.png)

Como podemos ver en la imagen, vemos que en la red interna(marcada en verde), esta en un rango donde varias maquinas tienen conexión entre si, por lo que como nos dice el reto, debemos conectarnos a un host diferente aparte del localhost, por lo que para averiguar que otro host tiene el puerto 8080 abierto(en este caso), haremos lo siguiente.

<br>

Primero interceptaremos la petición para ver como se tramita lo que nos interesa, como ya sabemos, la vulerabilidad esta en la función de comprobar existencias de un producto, por lo cual interceptaremos una peticion sobre eso:

![decode](/assets/images/LabsSSRF/lab2/decode.png)

Y ahora vemos lo siguiente que como sabemos lo tenemos que url-decodear como se ve en la imagen (usando ctrl + shift + u), y veremos la siguiente linea:

`stockApi=http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1`

Así que apreciamos que se esta conectando a una ip, la cual es **192.168.0.1**, pero en este caso debemos descubrir que otro host en la red tiene el puerto 8080 abierto, sabemos que en cada red pueden existir 255 hosts, por lo que usando BurpSuite haremos un ataque para ir descubriendo que ip nos responde un mensaje de estado true.

<br>

Para esto mandaremos la peticion a el intruder:

![intruder](/assets/images/LabsSSRF/lab2/intruder.png)

Como sabemos que existe la ruta /admin en este servidor, entonces es probable que exista en los otros host, por lo que nuestro payload del intruder quedará así.

Una vez tengamos la peticion en el intruder y le hayamos modificado lo de la ruta, ahora agregaremos donde irá el payload, que obviamente será en el ultimo valor de la ip, y al seleccionar ese apartado daremos a add y nos quedará así:

![add](/assets/images/LabsSSRF/lab2/add.png)

Así que nuestro payload quedaría como en la imagen.

Ahora vamos a la pestaña de payloads para cargar el ataque que queremos hacer:

![payload](/assets/images/LabsSSRF/lab2/payload.png)

Configuramos el payload de tipo numerico, que empieze desde el numero 1 hasta el 254 (el total de hosts), y que avance de 1 en 1.

Así que una vez configurado, daremos en start attack y después de un rato veremos que al filtrar por estado de respuesta vemos que recibimos una en estado true(200):

![doscientos](/assets/images/LabsSSRF/lab2/doscientos.png)

Podemos apreciar que recibimos esta respuesta, la cual es el panel del admin, y el host que nos respondio fue el 42.

Así que en la respuesta de esta petición buscaremos por la palabra delete, y encontaremos la API que nos permite eliminar usuarios:

![delete](/assets/images/LabsSSRF/lab2/delete.png)

Y vemos que el contenido para eliminar el usuario carlos es:

`http://192.168.0.42:8080/admin/delete?username=carlos`

Así que simplemenete agregaremos esta url a la petición original que esta en el intercept:

![intruder2](/assets/images/LabsSSRF/lab2/intruder2.png)

Quedandonos así, como si estuviesemos dandole al boton de eliminar usuario de carlos, pero esta vez es por medio de las peticiones, así que al tramitarla veremos que habremos terminado este laboratorio:

![final](/assets/images/LabsSSRF/lab2/final.png)

<br>

# Laboratorio 3: SSRF con filtro de entrada basado en lista negra

En el siguiente laboratorio, nos piden hacer lo siguiente:

![lab3](/assets/images/LabsSSRF/lab3/lab3.png)

Vemos que nos dice que debemos hacer algo similar a el laboratorio anterior, pero esta vez en desarrollador de la web ha implementado una función anti ataques SSRF, por lo que tendremos que encontrar una forma de burlar esta función.

El objetivo es eliminar a el usuario carlos por medio de una url que nos dan como base **http://localhost/admin**, así que iniciemos.

<br>

Primero interceptaremos la petición que sabemos es vulnerable a SSRF:

![peticion](/assets/images/LabsSSRF/lab3/peticion.png)

Podemos ver la petición que la hemos decodificado el formato de url-encode.

Si enviamos la petición así nos dará error:

![error](/assets/images/LabsSSRF/lab3/error.png)

Como vemos en la respuesta nos da error, ya que esta petición puede tramitarse pero el simbolo de "&" necesita estar url-encodeado, así que lo encodeamos y al tramitar de nuevo vemos que ahora si nos responde lo que debe:

![peticion2](/assets/images/LabsSSRF/lab3/peticion2.png)

Y vemos que nos funciona ya que el simbolo se url-encodea.

Ahora lo que intentaremos hacer es lo que nos pide, dice que debemos conectarnos a el host local y acceder a la ruta /admin desde la siguiente url:

`http://localhost/admin`

Y la agregaremos a la petición para ver que nos responde:

![blocked](/assets/images/LabsSSRF/lab3/blocked.png)

Podemos apreciar que en la respuesta vemos el mensaje "External stock check blocked for security reasons", por lo que esto es la función de seguridad anti-SSRF que nos dice el laboratorio que esta implementado en este nivel.

Así que una manera que pensamos de evadir esto es llamar a la ip en lugar del DNS de localhost quedando así:

`http://127.0.0.1/admin`

Y veremos que nos responde:

![blocked2](/assets/images/LabsSSRF/lab3/blocked2.png)

Podemos ver que de esta manera tampoco nos ha funcionado y nos sigue marcando el mensaje de seguridad.

<br>

Lo que intentaremos ahora será usar la ip pero esta vez en hexadecimal, el numero con el que empieza la ip (127) en hexadecimal es 0x7f y podemos darnos cuenta usando la función hex de python3:

![hex](/assets/images/LabsSSRF/lab3/hex.png)

Ahora como los valores que siguen de la ip de localhost son 001, simplemente las juntaremos formando en total el valor: "0x7f000001".

Así que probaremos con este valor en la petición del repeater:

![blocked3](/assets/images/LabsSSRF/lab3/blocked3.png)

Y vemos que nos da error, y si intentamos quitando la ruta admin:

![500](/assets/images/LabsSSRF/lab3/500.png)

Apreciamos que esta vez nos da un error de estado 500.

Por lo que esta manera tampoco nos ha funcionado.

<br>

Ahora probaremos de este modo, cuando en la ip hay numeros cero consecutivos por ejemplo: 127.0.0.1, se puede acortar a 127.1, ya que los 0 no se toman en cuenta, así que si hacemos esto en la petición veremos lo siguiente:

![200](/assets/images/LabsSSRF/lab3/200.png)

Vemos que esta vez nos ha dado un estado de respuesta 200, por lo que ya es buena señal ya que ahora nos esta dejando acceder a el contenido de localhost(la web principal) desde la misma peticion, pero ahora tendremos que acceder a la ruta /admin, y vemos que al agregar la ruta /admin vemos lo siguiente:

`http://127.1/admin`

![blocked4](/assets/images/LabsSSRF/lab3/blocked4.png)

Así que nuevamente nos esta bloqueando acceder a esa ruta, pero vemos que si es /admin nos da el mensaje de seguridad, pero en caso de ponerle algo que no exista, por ejemplo pondremos la ruta /prueba:

`http://127.1/prueba`

![prueba](/assets/images/LabsSSRF/lab3/prueba.png)

Y vemos que nos da un mensaje diferente al que nos da si ponemos /admin, por lo que nos damos cuenta que por detras debe haber algun filtro evitando que accedamos a la ruta /admin por medio del valor de nombre admin.

Así que ahora intentaremos acceder a la ruta sin poner el nombre de la ruta exactamente como se ve.

<br>

Ahora lo que intentaremos será url-encodear la letra "a" de "admin", para esto seleccionamos la letra "a" de admin, y damos a click izquierdo>convert-selection>URL>url-encode-all-characters.

Quedandonos así:

`http://127.1/%61dmin`

Y al tramitar la petición vemos que nos responde lo siguiente:

![admin](/assets/images/LabsSSRF/lab3/admin.png)

Vemos que nos da un error, así que tal vez nos este interpretando el simbolo de % como ese simbolo y no como parte de el url-encode, así que también url-encodearemos ese simbolo quedando así:

`http://127.1/%2561dmin`

Y ahora al tramitar la petición veremos lo siguiente:

![delete](/assets/images/LabsSSRF/lab3/delete.png)

Vemos que por fin hemos logrado acceder a /admin evadiendo el filtro de seguridad.

<br>

Ahora solo quedaría buscar la API de eliminar usuarios en el codigo de la petición:

![api](/assets/images/LabsSSRF/lab3/api.png)

Y ahora debemos poner esa funcion que hace en la url original del intercept:

`http://127.1/%2561dmin/delete?username=carlos`

![intercept](/assets/images/LabsSSRF/lab3/intercept.png)

Y al tramitarla habremos terminado con este laboratorio:

![final](/assets/images/LabsSSRF/lab3/final.png)

<br>

# Laboratorio 4: SSRF con omisión de filtro a través de vulnerabilidad de redirección abierta

En este laboratorio, podemos ver que nos pide hacer lo siguiente:

![lab4](/assets/images/LabsSSRF/lab4/lab4.png)

Nos dice que existe una función de verificar existencias, que obtiene los datos que muestra de un sistema de red interno.

También nos dice que devemos cambiar la URL de verificar existencias y reemplazarla por:

`http://192.168.0.12:8080/admin`

Que es un servidor interno el cual por el puerto 8080 corre un panel de administrador para eliminar usuarios, en este caso debemos eliminar el usuario carlos.

Y nos dice que la función de verificar existencias ya no nos permite ingresar URL como lo habiamos hecho en el laboratorio pasado, si no que ahora tendremos que buscar una redirección abierta, esto significa que debe ser una redirección a una parte de la web a la que nos deje acceder para modificar esa redirección por la que deseamos, que en este caso será http://192.168.0.12:8080/admin.

<br>

Entramos a el laboratorio, a un producto para ver la función de verificar existencias que sabemos, es vulnerable.

![funcion](/assets/images/LabsSSRF/lab4/funcion.png)

Como recordamos, esta es la función de verificar existencias similar a las de todos los laboratorios anteriores.

Así que al interceptar una petición de esa función veremos lo siguiente:

![encodeado](/assets/images/LabsSSRF/lab4/encodeado.png)

Como hemos visto esta url-encodeado, y seleccionamos la parte que nos interesa y la url-decodeamos con: ctrl+shift+u, una vez decodificada la url, se verá algo así:

![decodeado](/assets/images/LabsSSRF/lab4/decodeado.png)

`stockApi=/product/stock/check?productId=1&storeId=1`

Podemos apreciar que esta vez no esta llamando a algun servidor interno, si no que ahora esta llamando a una ruta de el servidor mismo.

la ruta es /product/stock/check, la cual esta ultima tiene un parametro del ID del producto.

Pero lo que nos llama la atención es que ya no se esta tramitando por medio de una url.

Así que para verificar si aún puede tramitar la petición por medio de una url dada, probaremos con la url de localhost:

`stockApi=http://localhost/`

Y vemos que nos dice lo siguiente en la respuesta:

![400](/assets/images/LabsSSRF/lab4/400.png)

Por lo que podemos ver en la respuesta, no nos acepta la url, y no es que haya un firewall bloqueando el acceso a localhost, simplemente en este apartado no admite las URL.

Por lo que intentaremos buscar dar por otro lado, investigando entre diferentes apartados de la web, descubrimos lo siguiente:

![next](/assets/images/LabsSSRF/lab4/next.png)

Un apartado que nos redirecciona a el siguiente articulo, y esto nos interesa esto ya que es diferente la petición a las que intente en otros lugares de la web.

Y esta petición al interceptarla nos muestra lo siguiente:

![redirect](/assets/images/LabsSSRF/lab4/redirect.png)

Podemos ver que al tramitar esa petición desde el repeater nos da un estado de respuesta 302, el cual significa que nos esta redirigiendo a algun lugar dentro de la página en este caso.

Y esto nos damos cuenta ya que en la parte de arriba de la petición vemos que nos esta tramitando la petición por el metodo GET, con el siguiente contenido:

`/product/nextProduct?currentProductId=1&path=/product?productId=2`

Vemos que esta accediendo a una ruta, similar a la primera petición que vimos, pero en este caso vemos un parametro extra el cual es **path**, y esta recibiendo una ruta de redirección.

Así que tal vez ese parametro admita URL, y nos permita hacer lo que queriamos en un principio.

Y para enterarnos si admite formato de URL, haremos lo siguiente:

Copiaremos la ruta que sabemos que existe, gracias a la petición de la redirección, la ruta es:

`/product/nextProduct?currentProductId=1&path=http://localhost`

Y vemos que en el parametro del path, hemos agregado la url de localhost, para así averiguar si nos responderá algo.

Después esta URL que hemos hecho, la pondremos en la petición primera que tuvimos, ya que esta petición erá la que ejecutaba algo que le dabamos, lo interpretaba en el apartado de verificar existencias, así que veremos lo que pasa, tenemos nuestra petición así:

![intruder](/assets/images/LabsSSRF/lab4/intruder.png)

`/product/nextProduct?currentProductId=1%26path=http://localhost`

> Como sabemos el simbolo de & debe ir en url-encode para evitar errores.

<br>

Y al tramitar esta petición, veremos en el navegador lo siguiente:

![funcion2](/assets/images/LabsSSRF/lab4/funcion2.png)

Vemos que en la parte de verificar existencias se ha interpretado la petición que hemos tramitado, por lo que es vulnerable, así que ahora en vez de llamar a la misma página, llamaremos a la web del servidor que esta en la red interna por el puerto 8080 que nos da el mismo laboratorio como reto, quedando así la petición:

`/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin`

![panel](/assets/images/LabsSSRF/lab4/panel.png)

Como vemos hemos mandado la petición principal a el repeater, y hemos visto que nos ha mostrado el panel de admin, el cual en el codigo de esa respuesta encontramos como ya sabemos lo de la API de eliminar usuario:

![delete](/assets/images/LabsSSRF/lab4/delete.png)

Por último agregaremos lo de esa API a la petición original, quedandonos así:

`/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin/delete?username=carlos`

![api](/assets/images/LabsSSRF/lab4/api.png)

Y al tramitar la petición se habrá eliminado al usuario carlos, y vemos que habremos terminado de resolver este laboratorio:

![end](/assets/images/LabsSSRF/lab4/end.png)

<br>

# Laboratorio 5: SSRF blind con detección fuera de banda(out of band)

En este laboratorio nos piden lo siguiente:

![lab5](/assets/images/LabsSSRF/lab5/lab5.png)

Vemos que nos dice que debemos esta página web utiliza un software de analisis, y este software lo que hace es tomar te la cabezera de la petición la parte de referencia, cuando abrimos algún producto.

Este tipo de peticiónes contienen en su cabecera inforamción útil para estos programas de analisis, lo que hace es como leímos, toma la URL de la referencia de la petición, esta referencia se refiere a de que lugar viene esta petición, por ejemplo si viene de algúna otra web donde hayan puesto el enlace a este producto en la referencia aparecera esa otra web de donde viene, y esto es util para el software y sacar analisis para saber de donde es que vienen sus vistas etc.

Pero nosotros usaremos esto para hacer algo.

Al abrir el laboratorio veremos la tienda común:

![tienda](/assets/images/LabsSSRF/lab5/tienda.png)

Y como recordamos nos decia que al abrir un producto sucede lo de la función de analisis, que lo que hace esa funcion es como dije tomar la URL y hacerle una petición a esa url referenciada.

Así que al interceptar la petición al abrir algún producto de la tienda veremos lo siguiente:

![referer](/assets/images/LabsSSRF/lab5/referer.png)

`Referer: https://0a96003804c1326a834e92c900a40009.web-security-academy.net/`

Podemos apreciar que nos esta haciendo referencia en este caso a la misma web en el header de la petición.

Así que sabemos que lo que hace la función que esta en el servidor web es ejecutar una petición hacia la URL que se encuentra en la referencia.

<br>

Así que para saber si es vulerabla a ataques SSRF, que nos permitiria en caso de funcionar, poder ejecutar recursos dentro del mismo sistema que como usuarios normales no tenemos acceso pero si lo hacemos desde su mismo servidor si que tendremos.

Así que modificaremos la URL y pondremos la del servidor tercero de BurpCollaborator, que como sabemos debemos dar en Burp>BurpCollaboratorClient.

![collaborator](/assets/images/LabsSSRF/lab5/collaborator.png)

Y una vez hecho esto, lo que haremos ahora será darle en Copy to clipboard para copiar el enlace del servidor temporal tercero de burpcollaborator.

<br>

Una vez tengamos la URL copiada, lo que haremos será pegar la URL en la cabecera donde dice referer en la petición:

![burp](/assets/images/LabsSSRF/lab5/burp.png)

`Referer: http://8y7er84x9d6yix39f09sdsnbv21tpi.burpcollaborator.net`

Quedandonos como se ve en la imagen anterior.

<br>

Ahora simplemente tramitaremos esa petición, y atraves de la respuesta del BurpCollaborator veremos lo siguiente al darle en pollnow:

![response](/assets/images/LabsSSRF/lab5/response.png)

Y como podemos ver, hemos tenido comunicación desde la parte de referencia hacia nosotros donde le indicamos que hiciera la petición, por lo que habremos terminado este laboratorio.

Este solo fue para mostrarnos y explicarnos la manera en que se comunica a la URL dada en la referencia de la cabecera de la petición.

Pero para hacer algo importante lo veremos en el laboratorio siguiente, así que habremos terminado este:

![end](/assets/images/LabsSSRF/lab5/end.png)

<br>

