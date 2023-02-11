---
layout: single
title: Laboratorios de DVWA inyecciones SQL - SQLi
excerpt: "En este post explicaremos la resolución del laboratorio SQLi del laboratorio de pruebas DVWA."
date: 2022-08-03
classes: wide
header:
  teaser: /assets/images/DVWA-SQLi/dvwa.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - mysql
  - SQLi
  - DVWA
---

<br>

# Inyección SQL - Nivel fácil

Cuando hayamos montado el sistema de práctica DVWA, podremos acceder y ver un menú con diferentes vulnerabilidades, en este caso haremos las de tipo SQLi.

El nivel fácil de inyección SQL normal se ve así:

![Inicio](/assets/images/DVWA-SQLi/SQLi-easy/inicio.png)

Vemos que tiene un apartado para ingresar datos, probaremos poner algún valor, en este caso el valor 1:

![1](/assets/images/DVWA-SQLi/SQLi-easy/id1.png)

Podemos apreciar que nos muestra que existe un usuario con el id 1, en este caso ese usuario es admin.

Probamos más números y nos dimos cuenta de que existe hasta el usuario 5.

![5](/assets/images/DVWA-SQLi/SQLi-easy/id5.png)

Vemos que este último usuario tiene de nombre Bob Smith.

<br>

Y cuando no existe un usuario, por ejemplo 6:

![6](/assets/images/DVWA-SQLi/SQLi-easy/id6.png)

Simplemente no nos muestra nada en caso de que el id de usuario no exista.

Ahora probaremos romper la consulta, como sabemos lo haremos con una comilla simple:

`1'`

De esta forma, y al tramitar este dato nos arroja el siguiente error:

![error](/assets/images/DVWA-SQLi/SQLi-easy/error.png)

Lo cual nos comienza a surgir ideas de que es vulnerable a SQLi, ya que nos marcó error directo de la base de datos.

Ahora intentaremos inyectar esta consulta:

`1' OR 1=1 -- -`

Y vemos que nos devuelve lo siguiente:

![users](/assets/images/DVWA-SQLi/SQLi-easy/allusers.png)

Podemos apreciar que nos interpretó nuestra consulta, nos escapó del campo User ID, y inyecto nuestra consulta que en este caso es OR 1=1, lo que hará que veamos todos los usuarios, ya que estamos comentando el resto de la consulta existente evitando limits o algo similar.

<br>

Ahora intentaremos descubrir cuantas columnas se están devolviendo a la respuesta del servidor web, en este caso sabemos que hay 2 campos, **First name** y **Surname**.

Por lo que intuimos que se devuelven 2 columnas, y esto lo verificaremos con **ORDER BY**:

`1' ORDER BY 2 -- -`

Y vemos esta respuesta:

![order2](/assets/images/DVWA-SQLi/SQLi-easy/orderby2.png)

Vemos que nos responde con algo, y sabemos que son 2 columnas las que se devuelven, ya que de lo contrario si ponemos un valor mayor que 2 nos dará este error:

![order3](/assets/images/DVWA-SQLi/SQLi-easy/orderby3.png)

Así que ya sabemos que son 2 columnas devueltas, ahora averiguaremos que tipo de dato está devolviendo, como en la respuesta vimos sabemos que está devolviendo strings, o sea texto, por lo que haremos esta consulta para verificarlo:

`1' UNION SELECT 'texto1','texto2' -- -`

Y como sospechábamos, si eran datos de texto los que devolvía estas columnas:

![strings](/assets/images/DVWA-SQLi/SQLi-easy/strings.png)

Podemos ver que se agregan las etiquetas 'texto1' y 'texto2' en lugar de sus valores por defecto.

<br>

Ahora intentaremos enumerar los nombres de bases de datos existentes, por lo que haremos la siguiente consulta:

`1' UNION SELECT schema_name, NULL FROM information_schema.schemata -- -`

Y podemos ver que nos enumera las bases de datos existentes:

![db](/assets/images/DVWA-SQLi/SQLi-easy/databases.png)

Y vemos que nos enumeró 2 bases de datos:

- information_schema
- dvwa

Sabemos que la base de datos information_schema es una por defecto que siempre viene y de ahí es donde enumeramos el resto, por lo que aparte de esa por defecto, vemos una que nos llama la atención, llamada dvwa.

Así que enumeraremos las tablas existentes dentro de esa base de datos:

`1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema = 'dvwa' -- -`

![tables](/assets/images/DVWA-SQLi/SQLi-easy/tables.png)

Vemos que nos enumeró 2 tablas:

- users
- guestbook

Así que enumeraremos las columnas de la tabla **users**, con esta nueva consulta:

`1' UNION SELECT GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_schema = 'dvwa' AND table_name = 'users' -- -`

Esta vez usamos la función GROUP_CONCAT() para que nos sea más fácil ver las columnas sin que se muestre tanto texto, así que nos respondió esto:

![columns](/assets/images/DVWA-SQLi/SQLi-easy/columns.png)

Vemos que nos enumeró las columnas de la tabla **users** y estas columnas son:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

Vemos muchas columnas, pero las que nos llaman la atención son **user** y **password**, por lo que procederemos a enumerarlas:

`1' UNION SELECT GROUP_CONCAT(user,':',password), NULL FROM dvwa.users -- -`

![data](/assets/images/DVWA-SQLi/SQLi-easy/data.png)

Podemos ver que nos enumeró el usuario y password, agregando el caracter : para separar ambas cosas.

Podemos ver que nos dumpeo estos datos:

- admin:5f4dcc3b5aa765d61d8327deb882cf99
- gordonb:e99a18c428cb38d5f260853678922e03
- 1337:8d3533d75ae2c3966d7e0d4fcc69216b
- pablo:0d107d09f5bbe40cade3de5c71e9e9b7
- smithy:5f4dcc3b5aa765d61d8327deb882cf99

Pero vemos que las contraseñas están hasheadas, por lo que intentaremos crackearlas.

En el sitio [CrackStation](https://crackstation.net) podemos crackear hashes básicos, como este es un nivel fácil, los hashes no deben ser complejos así que podemos tirar de esta web, y crackearlos:

![hashcrack](/assets/images/DVWA-SQLi/SQLi-easy/hashcrack.png)

Y como vemos nos ha crackeado todas las contraseñas de cada usuario:

- password
- abc123
- charley
- letmein
- password

Así que hemos completado el nivel fácil de este laboratorio.

<br>

# Inyección SQL - Nivel intermedio

Una vez seleccionado el nivel intermedio de dificultad vamos al apartado de SQLi, y veremos lo siguiente:

![medium](/assets/images/DVWA-SQLi/SQLi-medium/medium.png)

Ahora vemos que ha cambiado, ya no es un campo donde ingreses datos, sino que ahora es para seleccionar ya el dato.

Esto nos limita probar si es vulnerable a inyecciones SQL, ya que no nos deja ingresar texto directamente, pero lo que podemos hacer es optar por BurpSuite, e interceptar la petición, así que eso haremos.

![peticion1](/assets/images/DVWA-SQLi/SQLi-medium/peticion.png)

Como podemos ver, hemos interceptado la petición y esta la hemos pasado al repeater de burpsuite, y vemos que por el método POST se da este valor al parámetro id al seleccionar algún valor:

`id=1&Submit=Submit`

Y en la parte derecha vemos la respuesta.

Así que desde aquí intentaremos romper primeramente la consulta, quedando el valor id así:

`id=1&Submit=Submit`

Y vemos que nos responde esto:

![error](/assets/images/DVWA-SQLi/SQLi-medium/error.png)

El error de MariaDB SQL, por lo que ya podemos darnos la idea de que es vulnerable.

Así que ahora podremos intentar inyectar consultas, como sabemos primero contamos el número de columnas devueltas, así que usaremos ORDER BY:


`id=1 ORDER BY 2 -- -`

Como vemos en esta consulta ya no se usa la comilla para escapar de la consulta por defecto, ya que por detrás ya no se está indicando eso de '%UserID%' para obtener lo que el usuario puso en ese lugar de texto, y esto es porque ahora ya solo lo seleccionamos directamente de la lista que nos despliega.

Así que al tramitar la petición con ese parámetro modificado veremos que nos responde lo siguiente:

![order2](/assets/images/DVWA-SQLi/SQLi-medium/orderby2.png)

Podemos apreciar que no nos lanza ningún error, por lo que está interpretando nuestras consultas, probaremos indicándole en lugar de 2 un 3, para probar que responde:

`id=1 ORDER BY 3 -- -`

![order3](/assets/images/DVWA-SQLi/SQLi-medium/orderby3.png)

Podemos apreciar que nos marca un error, por lo que quiere decir que hay 2 columnas que se están devolviendo y no 3.

<br>

Ahora toca averiguar cuáles son las bases de datos existentes, por lo que haremos uso del método que ya conocemos:

`id=1 UNION SELECT GROUP_CONCAT(schema_name), NULL FROM information_schema.schemata -- -`

Y vemos que nos responde las bases de datos:

![databases](/assets/images/DVWA-SQLi/SQLi-medium/databases.png)

Y estas bases de datos son:

- information_schema
- dvwa

<br>

Como sabemos nos llama la atención la de nombre dvwa, por lo que crearemos una consulta para enumerar sus tablas:

`id=1 UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema = 'dvwa' -- -`

Este método es el que usamos en este tipo de inyecciones SQL basadas en errores, pero en este caso vemos la siguiente respuesta:

![err](/assets/images/DVWA-SQLi/SQLi-medium/err.png)

Podemos apreciar que nos marca error, cosa que antes en el nivel fácil no pasaba, la consulta esta bien, pero lo que sucede es que en este nivel intermedio nos dice lo siguiente:

*"El nivel medio utiliza una forma de protección de inyección SQL, con la función de "mysql_real_escape_string()". Sin embargo, debido a que la consulta SQL no tiene comillas alrededor del parámetro, esto no protegerá completamente la consulta para que no se modifique"*

Así que como el administrador de la base de datos intento protegerla de inyecciones sql, lo que hace esa función llamada mysql_real_escape_string(), es evitar que podamos ingresar caracteres como comillas, o comillas dobles, pero como no está bien protegida podemos hacer bypass usando codificación hexadecimal.

<br>

Lo que haremos es cambiar el texto de dvwa por ese texto, pero codificado en hexadecimal, lo haremos con un traductor o como quieras, y nos quedara así:

64,76,77,61

Simplemente eliminamos las comillas quedándonos con 64767761, y le agregamos un 0x para decirle que es valor hexadecimal, quedando la consulta así:

`id=1 UNION SELECT GROUP_CONCAT(table_name), NULL FROM information_schema.tables WHERE table_schema = 0x64767761 -- -`

Y ya nos responde las tablas de la base de datos dvwa:

![tab](/assets/images/DVWA-SQLi/SQLi-medium/tables.png)

Vemos que nos dumpeo las tablas:

- users
- guestbook

<br>

Ahora enumeraremos las columnas de la tabla users, ya que es la que nos llama la atención.

`id=1 UNION SELECT GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_schema = 0x64767761 AND table_name = 0x7573657273 -- -`

Y vemos que nos responde:

![columns](/assets/images/DVWA-SQLi/SQLi-medium/columns.png)

Nos da las siguientes columnas:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last
- login
- failed
- login

Y por último sacaremos los datos de las columnas user y password, ya que son las que nos llaman la atención:

`id=1 UNION SELECT GROUP_CONCAT(user,0x3a,password), NULL FROM dvwa.users -- -`

 Aquí no usamos hexadecimal, ya que no hay necesidad de usar comillas, solo en el carácter de ":" para separar el user de la password, pero fuera de eso no se usa, ya que ya sabemos donde está lo que nos interesa.

Y así veremos los usuarios y contraseñas que hemos dumpeado:

![dump](/assets/images/DVWA-SQLi/SQLi-medium/dump.png)

- admin:5f4dcc3b5aa765d61d8327deb882cf99
- gordonb:e99a18c428cb38d5f260853678922e03
- 1337:8d3533d75ae2c3966d7e0d4fcc69216b
- pablo:0d107d09f5bbe40cade3de5c71e9e9b7
- smithy:5f4dcc3b5aa765d61d8327deb882cf99

Y ya habremos terminado con este nivel intermedio.

<br>

# Inyección SQL - Nivel dificil

En el nivel difícil podemos apreciar que en la sección de inyección SQL ya no nos aparece algún lugar donde meter los datos o seleccionarlos como lo hicimos anteriormente:

![hard](/assets/images/DVWA-SQLi/SQLi-hard/hard.png)

Podemos apreciar que solo nos da una opción que para cambiar el ID ocupamos darle click, y al hacerlo nos abrirá otra ventana:

![other](/assets/images/DVWA-SQLi/SQLi-hard/other.png)

Y vemos que en esta página que se abrió contiene un cuadro para ingresar texto, y al ingresar algo y dar en submit vemos lo siguiente:

![submit](/assets/images/DVWA-SQLi/SQLi-hard/submit.png)

Vemos que nos mandó ese valor a la otra página, suponemos que esta data se está tramitando por el método POST, ya que no vemos nada de valores en la URL para deducir que se está tramitando por GET, así que abriremos el BurpSuite e interceptaremos la petición anterior:

![i1](/assets/images/DVWA-SQLi/SQLi-hard/intercept.png)

Como vemos se está tramitando por el método POST, así que ahora intentaremos romper la consulta para ver que nos responde, esta vez no usaremos el repeater, ya que queremos trabajar con la petición actual, ya que el resultado que nos interesa se verá reflejado en la web principal y no la que se abre, así que modificaremos la petición en el intercept del proxy, quedándonos así:

`id=1' OR 1=1 -- -`

![i2](/assets/images/DVWA-SQLi/SQLi-hard/intercept2.png)

Y esto nos responde al tramitar la petición:

![r1](/assets/images/DVWA-SQLi/SQLi-hard/respuesta1.png)

Vemos que nos dumpea todos los usuarios, omitiendo algún limit por detrás que quedo comentado, así que comprobamos que es vulnerable y empezaremos a averiguar cuantas tablas se están devolviendo usando como ya sabemos ORDER BY:

`1' ORDER BY 2-- -`

![orderby2](/assets/images/DVWA-SQLi/SQLi-hard/orderby2.png)

Y vemos que nos responde:

![r2](/assets/images/DVWA-SQLi/SQLi-hard/respuesta2.png)

Y vemos que nos responde sin error, ya que como sabemos en esta base de datos solo hay 2 columnas que se devuelven, ya que la base de datos es la misma lo que cambia es la forma de vulnerabilidad.

Así que ya sabemos que tiene 2 columnas que devuelve, por lo que ahora enumeraremos las bases de datos:

`id=1' UNION SELECT GROUP_CONCAT(schema_name), NULL FROM information_schema.schemata -- -`

![intercept3](/assets/images/DVWA-SQLi/SQLi-hard/intercept3.png)

Y vemos que nos responde:

![db](/assets/images/DVWA-SQLi/SQLi-hard/databases.png)

Podemos ver que nos lista 2 bases de datos:

- information_schema
- dvwa

Como ya sabemos ahora enumeraremos las tablas de dvwa:

`id=1' UNION SELECT GROUP_CONCAT(table_name), NULL FROM information_schema.tables WHERE table_schema = 0x64767761 -- -`

> Recordemos que se está usando un filtro para evitar inyecciones, pero no está bien adaptada, por lo que podemos evadir el filtro de comillas usando hexadecimal.

![i4](/assets/images/DVWA-SQLi/SQLi-hard/intercept4.png)

Y vemos que nos responde:

![r4](/assets/images/DVWA-SQLi/SQLi-hard/respuesta4.png)

Así que ya tenemos las tablas:

- users
- guestbook

<br>

Ahora enumeraremos las columnas de estas tablas, usando la siguiente consulta:

`id=1' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_schema = 0x64767761 AND table_name = 0x7573657273 -- -`

![i5](/assets/images/DVWA-SQLi/SQLi-hard/intercept5.png)

Y vemos que nos responde:

![r5](/assets/images/DVWA-SQLi/SQLi-hard/respuesta5.png)

Así que tenemos las columnas:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

<br>

Y por último dumpearemos los datos de las columnas que nos interesan, en este caso como sabemos user y password:

`id=1' UNION SELECT GROUP_CONCAT(user,'0x3a',password), NULL FROM dvwa.users -- -`

![i6](/assets/images/DVWA-SQLi/SQLi-hard/intercept6.png)

Esta consulta nos responderá:

![r6](/assets/images/DVWA-SQLi/SQLi-hard/respuesta6.png)

Y tenemos todos los usuarios y password dumpeados:

- admin:5f4dcc3b5aa765d61d8327deb882cf99
- gordonb:e99a18c428cb38d5f260853678922e03
- 1337:8d3533d75ae2c3966d7e0d4fcc69216b
- pablo:0d107d09f5bbe40cade3de5c71e9e9b7
- smithy:5f4dcc3b5aa765d61d8327deb882cf99

<br>

En este punto pasaremos a los niveles de las inyecciones SQL Blid.

<br>

# Inyección SQL Blind (ciega) - Nivel Fácil

En este desafío de SQL Blind podemos apreciar que al ingresar un valor en el campo que nos pide un valor vemos que en caso de que el id que dimos exista nos va a responder lo siguiente:

![exist](/assets/images/DVWA-SQLi/SQLiBlind-easy/exist.png)

Nos responde el mensaje "User ID exists in the database.", y en caso de que el valor id no exista nos devuelve el mensaje:

![missing](/assets/images/DVWA-SQLi/SQLiBlind-easy/missing.png)

"User ID is MISSING from the database."

Pero al parecer no nos está devolviendo ninguna columna, ya que no vemos algo más allá de eso, pero tenemos en cuenta que ya hay 2 posibilidades de respuesta, el exist y missing, algo como un verdadero y falso, ahora trataremos de buscar si es vulnerable a inyecciones SQL.

Primero interceptaremos una petición:

