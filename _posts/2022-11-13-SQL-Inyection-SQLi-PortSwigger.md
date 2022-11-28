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

![Gifts](/assets/images/SQLiPortswigger/lab1/Gifts.png)

Vemos que nos muestra este contenido, en la url vemos algo como esto:

![url](/assets/images/SQLiPortswigger/lab1/url.png)

<br>

Pero la parte que nos interesa es esta:

![url1](/assets/images/SQLiPortswigger/lab1/url1.png)

Como sabemos aquí está haciendo una consulta, y como ya explicamos antes por detrás la consulta se puede ver algo así:

`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

Y como la página del laboratorio nos dice que hay una vulnerabilidad en el filtro de categorías, intentaremos inyectar nuestras consultas sql para desplegar cosas interesantes.

También nos dice que el objetivo de este nivel es el siguiente:

Para resolver el laboratorio, realice un ataque de inyección SQL que haga que la aplicación muestre detalles de todos los productos en cualquier categoría, tanto lanzados como no lanzados.

Nos dice que quiere que mostremos todos los productos de cualquier categoría en un solo lugar, y también que se muestren los que están listos para lanzarse y los que aún no, lo cual esto nos recuerda a que hay posiblemente una columna llamada **released** con algún valor numérico, por lo que suponemos que este es el filtro para saber si algo está listo para mostrarse o no, así que ya sabemos el objetivo, mostrar todos los productos de todas sus categorías, tanto listos para lanzarse o no.

<br>

Sabemos que por detrás la consulta se ve algo así:

![consulta](/assets/images/SQLiPortswigger/lab1/consulta1.png)

La cual nos muestra que está seleccionando todo de la tabla **products**, y filtramos para que nos muestre donde algún valor de la columna **category** tenga el valor de **'Gifts'** y en la columna **released** tenga el valor 1. En caso de que en la columna **released** tenga el valor de 1, se retornara un valor **true** lo cual indica que nos dejara ver dicho contenido.

<br>

Y lo que haremos nosotros es que en la url la editaremos, para poder inyectar nuestras consultas, como ya sabemos el objetivo el cual es mostrar todos los productos de todas las categorías en un solo lugar y además mostrar también los productos que no están listos para mostrarse, o sea que no tienen valor 1 en **released**, por lo que primero haremos esto:

![url](/assets/images/SQLiPortswigger/lab1/Url1.png)

Vemos que en la url hemos agregado una comilla simple después de la categoría, y lo que estamos haciendo ahora, es cerrar el apartado de **category** que es **"Gifts"** y escaparnos de ese apartado para poder inyectar nuestras propias consultas, como vemos en la parte derecha, que agregamos el operador **OR**, el cual haremos un valor que nos de **true**, en este caso decimos, O que 1 sea igual a 1, lo cual es verdadero, dándonos permiso para desplegar todo lo de la tabla **products**, ya que el valor que filtraba lo de **released** estará comentado y no se interpretara, así que por detrás la consulta se vería algo así:

![query](/assets/images/SQLiPortswigger/lab1/query1.png)

<br>

Como podemos ver, la comilla simple que agregamos hizo que el apartado de **category** se cerrará y la otra comilla se recorrió después de nuestra consulta que queramos agregar, dándonos entrada a escribir nuestras consultas, que en este caso es el operador **OR** dandole un valor que nos responda con un **true**, para que nos valide esta consulta y mostrarnos todo lo de la tabla **products**, y como hemos agregado el operador **OR**, que en este caso como sabemos le indicamos algo para que nos devolviera un **true**, entonces nos mostrara todo, y el filtro de **released** no se ejecutara, ya que al final de nuestra consulta inyectada hemos puesto los guiones para indicarle que el resto de la consulta se comente y no se tome en cuenta, por eso la marque de un color gris, ya que no se tomara en cuenta en la consulta.

<br>

Por lo que ya no habrá filtros que respetar, mostrándonos todo lo de esa tabla en un solo lugar:

![respuesta](/assets/images/SQLiPortswigger/lab1/respuesta1.png)

Así que hemos logrado el objetivo de este laboratorio, mostramos todos los productos de todas las categorías en una sola parte, evadiendo el filtro de sí está listo para lanzarse o no, así que estamos viendo productos tanto lanzados como no lanzados, o sea que en **released** tenían un valor diferente a 1, por lo que la consulta se tornaría false y solo nos mostraría lo que estuviese en 1, pero como evadimos este filtro mostramos todo valor sea o no listo para mostrarse!

<br>

# Laboratorio 2: vulnerabilidad de inyección SQL que permite omitir el inicio de sesión (bypass)

En este segundo laboratorio, nos dice que tenemos un panel login vulnerable a SQLi, y nos dice que para resolverlo debemos hacer un bypass del usuario **administrator**, esto quiere decir que debemos encontrar una manera de acceder como el usuario **administrator** sin conocer su contraseña.

![lab2](/assets/images/SQLiPortswigger/lab2/lab2.png)

<br>

Al acceder al laboratorio nos encontramos con este panel login en la sección de "My account":

![login](/assets/images/SQLiPortswigger/lab2/login.png)

Desde aquí es donde probaremos inyectar nuestras consultas para ver si logramos hacer bypass en este panel usando el usuario **administrator**, así que primero, supondremos que por detrás se ejecuta alguna consulta similar a esta:

![consulta](/assets/images/SQLiPortswigger/lab2/consulta.png)

Aquí lo que nos interesa es que se está usando la tabla **users**, que dentro de esta puede haber columnas más interesantes que las que llama por defecto la consulta, vemos que después de hacer la selección de columnas en dicha tabla en este caso **users**, nos dice que donde el **username** y **password** que toman sus valores del panel login, coincidan con algún valor dentro de la tabla, entonces si esto se cumple nos va a dejar acceder al sistema.

Pero solo Conocemos el usuario más no la contraseña, por lo que intentaremos algo:

![login_bypass](/assets/images/SQLiPortswigger/lab2/login_bypass.png)

Lo que hicimos fue agregar el usuario, pero también agregamos una comilla simple para escapar de la consulta por defecto e inyectar nuestras propias consultas, esto se entiende más al ver como se interpretó la consulta por detrás:

![consulta_bypass](/assets/images/SQLiPortswigger/lab2/consulta_bypass.png)

Como podemos ver al agregar la comilla después de nuestro usuario lo que sucedió es que cerramos el campo de **username** para pasar a comentar el apartado de **password**, haciendo que eso ya no deba validarse con nuestros datos que pusimos en el cuadro de password del panel login, por lo que ahora la comilla que estaba antes paso a recorrerse hasta el final, pero como hemos comentado de resto todo, no nos afectara la otra parte gris de la consulta, ya que está comentada, y al hacer esto la base de datos interpretara esto como **true**, ya que solo nos está validando el **username** que en este caso es correcto, por lo que ya no verificara el apartado de **password** porque como dije antes esto ya está comentado e invalido, dejándonos acceder como dicho usuario al dar Log in, ya que todo lo que mencione se interpretara dándonos el resultado ya esperado.

<br>

Al hacer esto ya habremos completado el nivel y dejándonos un aviso de que hemos completado este laboratorio:

![fin](/assets/images/SQLiPortswigger/lab2/final.png)

<br>

# Laboratorio 3: Ataque UNION de inyección SQL, determinando el número de columnas devueltas por la consulta

Lo que nos dice este laboratorio, es que hay una vulnerabilidad nuevamente en el filtro de categorías de tipo SQLi, además de que los resultados de las consultas dentro de esta web, se muestran en pantalla, en este caso los productos que hemos visto serían los resultados, así que podríamos usar un ataque usando el operador **UNION**, para sacar datos de tablas, etc., pero antes de esto, antes de cualquier cosa, debemos saber cuantas columnas nos está devolviendo la consulta.

![determinar_columnas](/assets/images/SQLiPortswigger/lab3/determinar_columnas.png)

<br>

Así que nuestro objetivo principal es descubrir cuantas columnas se están devolviendo a la web para que nos muestre lo que vemos, primero al entrar a alguna categoría, en este caso **pets**, vemos que nos devuelve esto:

![pets](/assets/images/SQLiPortswigger/lab3/pets.png)

Primero haremos la prueba de la comilla simple para verificar si es vulnerable a SQLi, por lo que agregaremos una comilla simple a la url:

![consulta1](/assets/images/SQLiPortswigger/lab3/consultaweb1.png)

![err](/assets/images/SQLiPortswigger/lab3/error.png)

En este caso nos muestra este error, lo cual puede ser posible que sea vulnerable, por lo que ahora que ya sabemos que podría ser vulnerable, pasaremos a probar lo siguiente.

Cuando entramos al filtro de **pets**, podemos ver que en esta respuesta podemos intuir que se están devolviendo 3 columnas, el nombre, precio y los detalles, por lo que jugaremos con la cláusula **order by**, que viene en SQL, esto nos permitirá mezclar la cantidad de columnas devueltas y saber cuantas hay, así que al hacer esta consulta desde la URL:

![c2](/assets/images/SQLiPortswigger/lab3/consultaweb2.png)

Como vemos lo primero que hicimos fue dejar la comilla, esto para romper la consulta y que se invalide lo que nos iba a mostrar por defecto, en su lugar le pedimos que nos ordene las 3 primeras columnas devueltas, sabemos que son 3, ya que lo hemos intuido al contar las columnas visibles en lo que nos mostraría por defecto, así que en este caso si eran 3 y nos mostró esto:

![order](/assets/images/SQLiPortswigger/lab3/orderby.png)

Vemos que nos ha interpretado lo que le pedimos sin ningún error, sabemos que esta es la cantidad exacta de columnas devueltas, ya que de ser más, por ejemplo probemos con 4 en vez de 3:

![err](/assets/images/SQLiPortswigger/lab3/error.png)

Rápidamente nos arroja este aviso de error, ya que no pudo interpretar lo que le dijimos, ya que solo hay 3 columnas devueltas y no 4.

<br>

Una vez sepamos la cantidad de columnas devueltas, en este caso 3, lo siguiente será usar **UNION SELECT** para de todas las columnas devueltas, agruparlas:

![c3](/assets/images/SQLiPortswigger/lab3/consultaweb3.png)

Aquí lo que hicimos fue agregar el **UNION SELECT** a la url, para que después sea interpretado por la consulta, seguido de 3 valores los cuales asignamos como **NULL**, ya que si poníamos número, o string, no nos deja.

> Si hubiese más columnas devueltas hay más probabilidad de que alguna de ellas nos aplique las etiquetas de número o string, y poder inyectar nuestras consultas basadas en error, pero en este caso son pocas que no sucede eso.

Por lo que al hacer esto estaremos mezclando los valores de dichas columnas junto con el valor **NULL**, que en este caso no se muestra nada, pero el objetivo de este laboratorio era determinar el número de columnas devueltas jugando con **UNION SELECT**, por lo que al tramitar la petición de la url estaremos completando este nivel:

![fin](/assets/images/SQLiPortswigger/lab3/fin.png)

<br>

# Laboratorio 4: Ataque UNION de inyección SQL, encontrando una columna que contiene texto

Buscar una columna que interpreta cadenas de texto, nos puede servir para después inyectar nuestras consultas directamente, pero primero necesitamos encontrar que columnas devueltas aceptan texto.

![4](/assets/images/SQLiPortswigger/lab4/lab4.png)

Para ello, nos dan un laboratorio el cual como sabemos, en la web principal nos dice que es vulnerable a SQLi dentro del filtro de categorías, por lo que primero iremos a ello:

![category](/assets/images/SQLiPortswigger/lab4/Gifts.png)

Vemos que primero estamos en este filtro de la categoría **Gifts**, vemos que la url se ve así:

![url](/assets/images/SQLiPortswigger/lab4/url.png)

Y para resolver este laboratorio debemos mostrar esta cadena de texto en una columna devuelta que admita cadena de texto, también llamadas strings:

![string](/assets/images/SQLiPortswigger/lab4/string.png)

Como vemos, en esta parte nos dice que hagamos que la base de datos nos devuelva el valor "VqagHe" en el valor de la columna.

<br>

Ya sabemos el objetivo, así que primero iniciaremos descubriendo el número de columnas devueltas, que lo haremos como sabemos con **order by** y **UNION SELECT**:

![url2](/assets/images/SQLiPortswigger/lab4/url2.png)

![orderby](/assets/images/SQLiPortswigger/lab4/orderby.png)

Como vemos hemos descubierto que el número de columnas devueltas es 3, por lo que ahora usando **UNION SELECT** descubriremos cuál de las 3 columnas interpreta texto, probamos con la primera y:

![1](/assets/images/SQLiPortswigger/lab4/1.png)

Vemos que en la url hemos dicho que en lugar del primer NULL, nos muestre un valor de texto, y al intentar tramitar esta petición el servidor nos responde con esto:

![error](/assets/images/SQLiPortswigger/lab4/error.png)

Por lo que ahora probaremos con el valor de la segunda columna:

![2](/assets/images/SQLiPortswigger/lab4/2.png)

Y como vemos esta vez nos ha interpretado, ya que esta columna es de valor string, lo cual nos permitió inyectar nuestro texto, aunque podríamos inyectar código, pero esto aún no, por lo que como vemos arriba nos dice que hemos completado este nivel, ya que logramos mostrar ese valor string en lugar de una columna, la cual podemos ver al final de la tabla:

![fin](/assets/images/SQLiPortswigger/lab4/final.png)
