---
layout: single
title: Inyección SQL - SQLi
excerpt: "Explicación de como resolver los laboratorios de PortSwigger sobre SQL inyection SQLi."
date: 2022-11-13
classes: wide
header:
  teaser: /assets/images/SQLiPortswigger/SQLips.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - mysql
  - SQLi
  - Portswigger
---

# Laboratorio 1: vulnerabilidad de inyección SQL en la cláusula WHERE que permite la recuperación de datos ocultos

<br>

En este primer laboratorio, veremos algo básico, como ya hemos visto en el título, jugaremos con la cláusula **WHERE** para recuperar datos de las tablas dentro de la base de datos.

![Lab1](/assets/images/SQLiPortswigger/lab1/Lab1.png)


<br>

Como vemos en la imagen esto es lo que nos muestra en el laboratorio 1, nos dice que este laboratorio contiene una vulnerabilidad tipo SQL inyection, en el filtro de la categoría producto, y cuando hacemos una petición sobre alguna categoría, en este caso usaremos la categoría **"Gifts"** y por detrás se interpreta una consulta que es así:

`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

Que como ya sabemos, primero se selecciona todo el contenido de la tabla **products**, para después filtrar datos donde **category** tenga un valor en formato string el cual es **Gifts**, y por ultimo nos dice que **relased**, debe ser igual a 1.

Este último nombre **released**, nos da a entender que hay más datos que no podemos ver, ya que como sabemos released significa "liberado", por lo que debe haber cosas que aún no se han liberado, y por lógica deben tener un valor que no sea 1, para que no se muestren antes de tiempo.

<br>

Ahora que conocemos un poco la consulta vayamos a desplegar el laboratorio en el botón que dice "Acces the lab".

Una vez dentro nos encontraremos con esta página que nos desplegá el laboratorio:

![Lab1](/assets/images/SQLiPortswigger/lab1/web1.png)

<br>

Vemos que al parecer es un tipo de tienda online, arriba hay un indicador que nos dice si hemos terminado el laboratorio o no, y ya de primera vista estamos viendo un filtro de categorías:

![categories](/assets/images/SQLiPortswigger/lab1/categories.png)

<br>

Como la categoría que nos dijeron al inicio, así que ya tenemos por donde empezar!

Recordemos que al inicio nos dicen que existe una vulnerabilidad SQLi en el filtro de categoría, por lo que accederemos a alguna de esas categorías, en este caso ingresaremos a la categoría de **"Gifts"**, y al abrir esa categoría vemos esta respuesta de la página:

![Gifts](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/Gifts.png)

Vemos que nos muestra este contenido, en la url vemos algo como esto:

![url](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/url.png)

<br>

Pero la parte que nos interesa es esta:

![url1](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/url1.png)

Como sabemos aquí está haciendo una consulta, y como ya explicamos antes por detrás la consulta se puede ver algo así:

`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

Y como la página del laboratorio nos dice que hay una vulnerabilidad en el filtro de categorías, intentaremos inyectar nuestras consultas sql para desplegar cosas interesantes.

También nos dice que el objetivo de este nivel es el siguiente:

Para resolver el laboratorio, realice un ataque de inyección SQL que haga que la aplicación muestre detalles de todos los productos en cualquier categoría, tanto lanzados como no lanzados.

Nos dice que quiere que mostremos todos los productos de cualquier categoría en un solo lugar, y también que se muestren los que están listos para lanzarse y los que aún no, lo cual esto nos recuerda a que hay posiblemente una columna llamada **released** con algún valor numérico, por lo que suponemos que este es el filtro para saber si algo está listo para mostrarse o no, así que ya sabemos el objetivo, mostrar todos los productos de todas sus categorías, tanto listos para lanzarse o no.

<br>

Sabemos que por detrás la consulta se ve algo así:

![consulta](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/consulta1.png)

La cual nos muestra que está seleccionando todo de la tabla **products**, y filtramos para que nos muestre donde algún valor de la columna **category** tenga el valor de **'Gifts'** y en la columna **released** tenga el valor 1. En caso de que en la columna **released** tenga el valor de 1, se retornara un valor **true** lo cual indica que nos dejara ver dicho contenido.

<br>

Y lo que haremos nosotros es que en la url la editaremos, para poder inyectar nuestras consultas, como ya sabemos el objetivo el cual es mostrar todos los productos de todas las categorías en un solo lugar y además mostrar también los productos que no están listos para mostrarse, o sea que no tienen valor 1 en **released**, por lo que primero haremos esto:

![url](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/Url1.png)

Vemos que en la url hemos agregado una comilla simple después de la categoría, y lo que estamos haciendo ahora, es cerrar el apartado de **category** que es **"Gifts"** y escaparnos de ese apartado para poder inyectar nuestras propias consultas, como vemos en la parte derecha, que agregamos el operador **OR**, el cual haremos un valor que nos de **true**, en este caso decimos, O que 1 sea igual a 1, lo cual es verdadero, dándonos permiso para desplegar todo lo de la tabla **products**, ya que el valor que filtraba lo de **released** estará comentado y no se interpretara, así que por detrás la consulta se vería algo así:

![query](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/query1.png)

<br>

Como podemos ver, la comilla simple que agregamos hizo que el apartado de **category** se cerrará y la otra comilla se recorrió después de nuestra consulta que queramos agregar, dándonos entrada a escribir nuestras consultas, que en este caso es el operador **OR** dandole un valor que nos responda con un **true**, para que nos valide esta consulta y mostrarnos todo lo de la tabla **products**, y como hemos agregado el operador **OR**, que en este caso como sabemos le indicamos algo para que nos devolviera un **true**, entonces nos mostrara todo, y el filtro de **released** no se ejecutara, ya que al final de nuestra consulta inyectada hemos puesto los guiones para indicarle que el resto de la consulta se comente y no se tome en cuenta, por eso la marque de un color gris, ya que no se tomara en cuenta en la consulta.

<br>

Por lo que ya no habrá filtros que respetar, mostrándonos todo lo de esa tabla en un solo lugar:

![respuesta](/home/dansh/Webserver/dantedansh.github.io/assets/images/SQLiPortswigger/lab1/respuesta1.png)

Así que hemos logrado el objetivo de este laboratorio, mostramos todos los productos de todas las categorías en una sola parte, evadiendo el filtro de sí está listo para lanzarse o no, así que estamos viendo productos tanto lanzados como no lanzados, o sea que en **released** tenían un valor diferente a 1, por lo que la consulta se tornaría false y solo nos mostraría lo que estuviese en 1, pero como evadimos este filtro mostramos todo valor sea o no listo para mostrarse!

