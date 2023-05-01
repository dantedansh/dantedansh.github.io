---
layout: single
title: SSRF - Laboratorios de PortSwigger
excerpt: "En este post, explicaremos ¿Que es? y como se realiza un ataque SSRF, server side request forgery."
date: 2023-04-25
classes: wide
header:
  teaser: /assets/images/LabsSSRF/
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

Una vez tengamos la peticion en el intruder y le hayamos modificado lo de la ruta, ahora agregaremos donde irá el payload, que obviamente será en el ultimo valor de la ip, y al seleccionar ese apartado daremos a add y nos quedará así:

![add](/assets/images/LabsSSRF/lab2/add.png)

Como sabemos que existe la ruta /admin en este servidor, entonces es probable que exista en los otros host, por lo que nuestro payload del intruder quedará así.

Así que nuestro payload quedaría como en la imagen.

Ahora vamos a la pestaña de payloads para cargar el ataque que queremos hacer:

![payload](/assets/images/LabsSSRF/lab2/payload.png)

Configuramos el payload de tipo numerico, que empieze desde el numero 1 hasta el 254, y que avance de 1 en 1.

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