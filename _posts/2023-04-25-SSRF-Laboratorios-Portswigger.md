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
