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

<br>

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

# Laboratorio 9: Ataque de inyección SQL, enumerando el contenido de la base de datos en bases de datos que no son de Oracle

En este laboratorio, nos dicen que debemos dumpear contenido de una tabla dentro de una base de datos, el nivel nos dice esto:

![lab9](/assets/images/SQLiPortswigger/lab9/lab9.png)

Como en los niveles anteriores, la vulnerabilidad sigue siendo la del filtro en las categorias, entonces ahí empezaremos, pero después nos dice que dentro de esta base de datos hay una tabla que contiene nombres de usuario y contraseñas, pero en este caso no nos estan diciendo el nombre de las tablas ni mucho menos de las columnas, por lo que ahora lo investigaremos por nuestra cuenta, nos dice que para completar este laboratorio debemos acceder al panel login como el usuario **administrator**, cuya contraseña debemos descubrir.

Al ir a la parte vulnerable del laboratorio vemos lo siguiente:

![respuesta1](/assets/images/SQLiPortswigger/lab9/respuesta1.png)

Como recordamos, podemos intuir que en este caso podemos saber que probablemente hay 2 columnas devueltas, la del titulo del texto y el texto en si, por lo que con **ORDER BY** o directamente jugando con **UNION SELECT** podemos comprobar que en efecto tiene 2 columnas, y también descubrimos que ambas aceptas strings, ya que interpretan texto por lo que vemos en la respuesta o sea el titulo y descripcion de ese titulo, nuestra consulta queda algo así:

![consulta1](/assets/images/SQLiPortswigger/lab9/consulta1.png)

Y la respuesta de esta nos muestra:

![respuesta2](/assets/images/SQLiPortswigger/lab9/respuesta2.png)

Vemos que nos interpreta lo que le hemos dicho, ya que la columna es de tipo string, por lo que ahora trataremos de intuir que tipo de base de datos usa, sabemos que no usa Oracle, ya que el mismo nivel lo dice, ademas podemos saberlo porque no estamos usando la tabla **dual**, así que nos quedan Microsoft,MySQL y PostgreSQL, así que probe con **@@version** y me marco error, por lo que la unica opcion que quedaba era la de PostgreSQL que es **version()**, ya que Microsoft y MySQL son similares en cuanto a este caso, y esto lo puedes recordar viendo la hoja de trucos:

![ver](/assets/images/SQLiPortswigger/lab9/dbversion.png)

Así que nuestra consulta quedo así:

![ver](/assets/images/SQLiPortswigger/lab9/postgreSQL.png)

Y nos respondio:

![respuesta3](/assets/images/SQLiPortswigger/lab9/respuesta3.png)

Y como sabemos que version es ahora empezaremos a enumerar en base a la sintaxis de PostgreSQL.

<br>

Primero empezaremos a descubrir que bases de datos existen, para ello crearemos la siguiente consulta:

![databases](/assets/images/SQLiPortswigger/lab9/databases.png)

Estamos indicando que en la primera columna, en esa posicion nos muestre el nombre de esquema **schema_name**, esto son las bases de datos, y las consultas para obtenerlas las pusimos a la derecha, alado de la columna 2, le decimos que de la base de datos **information_schema** nos de los valores de la tabla **schemata**, y en medio de estos 2 valores ponemos un **.** para poder separarlos y la base de datos sepa que esta haciendo una consulta de la base de datos **schema_name** a la tabla **schemata**.

Y ahora que sabemos que es esto, veremos lo que nos responde el servidor:

![respuesta4](/assets/images/SQLiPortswigger/lab9/respuesta4.png)

Podemos apreciar que nos ha respondido y nos ha dumpeado varias bases de datos, entre ellas:

- **information_schema**
- **public**
- **pg_catalog**

Así que la que nos llama la atencion es la que se llama la atencion la tabla de **public**, por lo que sacaremos las tablas de dicha base de datos con la siguiente consulta:

`https://web-security-academy.net//filter?category=Gifts' UNION SELECT table_name,'texto 2' FROM information_schema.tables WHERE table_schema = 'public' -- -`

> Puse la consulta en este formato ya que es muy grande, y recuerda que no es necesario indicar la base de datos cuando las tablas que buscas estan en la base de datos ya en uso, pero en este caso lo use para que se entienda bien todo.

Lo que estamos haciendo es primero en el lugar de la primera columna nos mostrara las tablas, estas tablas las obtendremos de la base de datos **information_schema** y dentro de su tabla **tables**, obtendremos las tablas donde el nombre de la base de datos **table_schema** se llame **public**.

Y estas son las tablas que obtendremos:

![respuesta5](/assets/images/SQLiPortswigger/lab9/respuesta5.png)

Vemos que obtuvimos las tablas:

- products
- users_lwkejd

De la base de datos **public**.

Ahora que ya conocemos la tabla que nos importa **users_lwkejd** toca descubrir sus columnas, así como lo vemos en la siguiente consulta:

`https://web-security-academy.net//filter?category=Gifts' UNION SELECT column_name,'texto 2' FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users_lwkejd' -- -`

Aquí le estamos indicando que ahora en la parte de la primera columna nos mostrara las columnas, estas columnas las obtendra de la base de datos **information_schema** en su tabla **columns**, obtendremos las columnas donde el nombre de la base de datos **table_schema** se llame **public**, y despues agregamos el operador AND, para indicarle que también donde la tabla se llame **users_lwkejd**, y esto nos respondera:

![respuesta6](/assets/images/SQLiPortswigger/lab9/respuesta6.png)

Podemos ver abajo en el lugar de la primera columna que hemos obtenido los nombres de las columnas de la tabla **users_lwkejd**, que en este caso las columnas son:

- **username_nemdqx**
- **password_ypezho**

Ahora solo queda dumpear los datos de esas columnas, que haremos con la siguiente consulta:

`https://web-security-academy.net//filter?category=Gifts' UNION SELECT username_nemdqx,password_ypezho FROM public.users_lwkejd -- -`

Aqui le estamos indicando que nos muestre lo que hay en las columnas **username_nemdqx** y **password_ypezho** reemplazandolos en lugar de las columnas originales, bueno más bien mezclando, después le decimos que esto lo obtendra de la base de datos **public** en la tabla **users_lwkejd**, y podremos dumpeaer las credenciales como vemos aqui:

![dump](/assets/images/SQLiPortswigger/lab9/dump.png)

Como podemos apreciar hemos dumpeado los datos de dichas columnas, y ya solo queda tomar las credenciales del usuario **administrator** para terminar el laboratorio:

![final](/assets/images/SQLiPortswigger/lab9/final.png)
