---
layout: single
title: Introducción a Inyecciónes SQL - SQLi
excerpt: "Explicación de que son, como se detectan y como se explotan las vulnerabilidades de tipo SQLi, Esta es una introducción a las inyecciones SQL, en otros post seguiremos resolviendo y explicando más laboratorios sobre inyecciones SQL para practicar."
date: 2022-08-03
classes: wide
header:
  teaser: /assets/images/SQLi/SQLi.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - mysql
  - SQLi
  - TryHackMe
---

<br>

**Índice de contenido**

- [¿Que es SQL?](#id1)
- [¿Cómo está conformada una base de datos?](#id2)
- [¿Cómo está conformada una tabla de datos?](#id3)
- [Bases de datos relacionales y no relacionales](#id4)
- [Creando una base de datos para la prueba](#id5)
- [Formas de filtrar los datos de una tabla](#id6)
- [cláusula "where" para filtrar datos específicamente](#id7)
- [cláusula "like" para filtrar datos no específicamente](#id8)
- [La instrucción UNION](#id9)
- [La instrucción INSERT](#id10)
- [La instrucción UPDATE](#id11)
- [La instrucción DELETE](#id12)
- [¿Que es SQLi?](#id13)
- [Tipos de Inyecciones SQL](#id14)
- [Prueba de inyección Basada en errores (practica en Acuentix)](#id15)
- [Inyección SQL Basada en errores (Prueba en TryHackMe)](#id16)
- [Bypass de autenticación (BLIND SQLi)](#id17)
- [Basado en Booleanos (Blind SQLi)](#id18)
- [Basado en Tiempo (Blind SQLi)](#id19)

<div id='id1' />

<br>

# ¿Que es SQL?

Antes de ver **SQLi** debemos saber como funciona **SQL**, es un lenguaje de consulta estructurada, esto quiere decir que con las consultas también llamadas declaraciones, nos sirve para manipular una base de datos y organizar información en forma de bases de datos relacionales.

<br>


<div id='id2' />

# ¿Cómo está conformada una base de datos?

![Tabla](/assets/images/SQLi/DBMS.png)

En el primer bloque vemos que está el servidor de la base de datos, que este es el que contiene las bases de datos dentro de ella.

Después vemos que en la base de datos "Escuela" tiene 2 tablas, una de Alumnos y otra de Aulas, y cada tabla tiene sus respectivos valores que se asignaron en el DBMS.

Al lado derecho vemos otra base de datos que es prácticamente lo mismo pero con diferente información, pero vemos que es posible tener más de 1 base de datos dentro del servidor de bases de datos.

<br>

<div id='id3' />

# ¿Cómo está conformada una tabla de datos?

Debemos recordar que una tabla en **MySQL** se conforma por partes:

![Tabla](/assets/images/SQLi/tabla.png)

Vemos que está conformada por filas y columnas, debemos saber esto, ya que lo necesitaremos más adelante.

<br>

**Columnas:**

Las columnas solo pueden tener un nombre único por tabla, por ejemplo la columna de una tabla tiene estos datos "id", "usuario" "contraseña", y estos no se pueden repetir como lo vemos aquí:

![Tabla](/assets/images/SQLi/tabla1.png)

Vemos que cada columna de cada tabla tiene un nombre distinto, esto es lo que los diferencia, cada una de estas antes de declararse en el **DBMS** debe ser asignado el tipo de dato que se guardara dentro de esa tabla, ya sea caracteres, números etc. **DBMS** es donde gestionamos la base de datos, que veremos más adelante.

Esto nos sirve además de tener control de nuestros datos, nos informa cuando un dato que no corresponde a su tipo que se ingresó nos muestra un error diciéndonos para poder corregir lo que sea necesario.

Una columna que contenga de valor un número puede generar un *"key field"*, que esto nos sirve para poder ir aumentando conforme crece la fila subsiguiente, al hacerlo crea lo que llamamos *"key field"* y esto lo podemos usar para encontrar esa fila exacta en una consulta SQL.

<br>

**Filas:**

Las filas son las que contienen los campos de datos separados, cuando se agregan datos a una tabla se crea una fila la cual contendrá estos datos.

como se ve a continuación:

![Tabla](/assets/images/SQLi/tabla2.png)

<br>

<div id='id4' />

# Bases de datos relacionales y no relacionales

**Relacional:**

Una **base de datos relacional** es la que guarda datos en tablas y es común que se compartan información entre ellas, y estas tablas usan columnas para saber de qué son los datos que estás mostrando en esa tabla, y las filas son los datos para esas columnas que especificamos, por ejemplo la columna "Nombre" puede tener una fila con un dato conforme al valor de lo que definimos anteriormente, por ejemplo un nombre seria "Dansh".

Estas tablas comúnmente contienen una **ID** que esta **ID** se puede usar para hacer referencia a ellas en otras tablas y como comparten información se le llama **"Base de datos Relacional"**.

**No Relacional:**

Y la **base de datos no relacional** que se les llama NoSQL, a las relacionales se les dice MySQL, entonces como esta es **no relacional** no usa ni tablas, ni columnas ni filas, esto lo almacena como si fuese un documento con una estructura básica como **XML** o **JSON**, y cada registro se le asigna una clave única para poder ubicar esos datos.


<br>

<div id='id5' />

# Creando una base de datos para la prueba

Primero debemos iniciar el servicio mysql desde la terminal:

`service mysql start`

> Si no tienes instalado el servicio mysql se instala con: `sudo apt install default-mysql-server` en la terminal.

Ahora como root nos conectaremos al servidor de la base de datos:

`mysql -u root`

En este momento se nos desplegará una consola interactiva de mariaDB, que es un DBMS, ahora le diremos que nos muestre las bases de datos disponibles:

`MariaDB [(none)]> show databases;`

Y nos mostrará:

![Show](/assets/images/SQLi/show.png)

Vemos que por defecto hay 3 bases de datos, nosotros agregaremos una para la prueba con **create database**:

`MariaDB [(none)]> create database Escuela;`

Esto nos habrá creado la base de datos **Escuela**, y podemos comprobarlo al volver a ejecutar show databases:

![Escuela](/assets/images/SQLi/Escuela.png)

Como vemos se agregó la base de datos **Escuela** al servidor de bases de datos.

Ahora debemos usar esa base de datos por lo que hacemos con **use**:

`MariaDB [(none)]> use Escuela;`

Una vez estemos conectados a la base de datos **Escuela**, como esta base de datos no tiene tablas crearemos una:

`MariaDB [Escuela]> create table Alumnos(id int(2), usuario varchar(30), contraseña varchar(30));`

Primero, estamos creando la tabla con el nombre **Alumnos**, esta tabla estará dentro de la base de datos **Escuela**.

Después le pasaremos las columnas que creara con su respectivo tipo de dato que almacenara en forma de filas, por ejemplo la columna id contendrá información de tipo entero con 2 espacios de caracteres, después en la columna usuario contendrá 30 espacios de tipo carácter o sea letras, y así crear una fila con ese tipo de dato almacenada, después en contraseña es similar.

Ahora veremos esta tabla recién creada usando **show table**:

![Tabla1](/assets/images/SQLi/tabla1_escuela.png)

En la imagen vemos que efectivamente, se creó la tabla con sus respectivos tipos de datos.

Ahora para ver como esta conformada esta tabla podremos usar **describe**:

`MariaDB [Escuela]> describe Alumnos;`

Y esto nos va a mostrar la información de esta tabla más detallada:

![describe](/assets/images/SQLi/describe.png)


Ahora para agregar datos a esta tabla lo que hacemos es usar el **insert**:

`MariaDB [Escuela]> insert into Alumnos(id, usuario, contraseña) values(1, "ryzen", "Admin3!!$");`

Esta línea lo que hizo fue agregar datos a esta tabla, obviamente debemos pasar los datos correspondientes a sus columnas, primero se usa el **insert** para insertar datos y después el **into** para decirle donde insertara esos datos, después le decimos que los insertara en la tabla **Alumnos**, y posteriormente pasamos los nombres que pusimos a las columnas seguido de los valores con **value** y lo hacemos respetando su orden y tipo de dato.


![insert](/assets/images/SQLi/insert1.png)

Vemos que hemos ingresado el **insert** anterior y 2 **insert** más.

> Recuerda que cuando se usa **describe** no se está mostrando los datos de la tabla sino su forma de como está hecha, para ver los datos de la tabla se usa otro comando que veremos ahora llamado **select**.

Para ver los datos de una tabla se usa **select** como veremos a continuación:

`MariaDB [Escuela]> select * from Alumnos;`

Aquí le estamos indicando que seleccione * Todo lo de la tabla **Alumnos**.

Y al hacer esto nos mostrará como le dijimos, todos los datos de la tabla **Alumnos**:

![select](/assets/images/SQLi/select1.png)

> SQL no diferencia entre mayúsculas y minúsculas.

<br>

<div id='id6' />

# Formas de filtrar los datos de una tabla

El primer comando que usaremos es **select**, ya lo usamos anteriormente, pero no solo nos sirve para mostrar lo que le digamos, tiene más funciones.

> **select** nos sirve para actualizar, eliminar o insertar datos de una tabla.

Como recordamos al hacer:

`MariaDB [Escuela]> select * from Alumnos;`

Esto nos seleccionaba todo lo de la tabla alumnos y posteriormente nos lo mostraba todo, pero también hay maneras de filtrar por si queremos algo en específico.

Si queremos filtrar por algunas columnas en específico y no mostrarnos todo como lo hicimos hace un momento con el signo de * ahora en lugar de ese signo le diremos las columnas que queremos que nos muestre:

`MariaDB [Escuela]> select id,contraseña from Alumnos;`

Esto nos va a seleccionar las columnas que especificamos, en este caso son **id** y **contraseña** de la tabla **Alumnos** y luego las mostrara:

![selectesp](/assets/images/SQLi/select_especifico.png)

<br>

Ahora el comando que sigue es **LIMIT**, esto nos va a permitir saltar y mostrar solo una fila o a partir de una fila hacia abajo, por ejemplo:

`MariaDB [Escuela]> select * from Alumnos LIMIT 1;`

Aquí le estamos indicando que nos seleccione todo de la tabla **Alumnos** para después con **LIMIT** mostrarnos limitando el número de filas que saltara y mostrara a partir de una fila en base a los valores que le pasaremos, en este caso solo pusimos 1, que esto significa que solo nos mostrara la primera fila y el resto no, se verá así:

![limit](/assets/images/SQLi/limit1.png)

> Cuando pasamos solo un valor y no 2 entonces se tomara ese valor como las primeras filas que quieres ver empezando desde la primera.

<br>

Ahora si queremos omitir la primera fila, pero mostrar las siguientes 2 entonces hacemos:

`MariaDB [Escuela]> select * from Alumnos LIMIT 1,2;`

Y veremos que nos saltó la primera fila, y a partir de la que sigue de la que saltamos nos mostró las 2 que seguían hacia abajo viéndose así:

![limit2](/assets/images/SQLi/limit1-2.png)

> LIMIT X,Y en el valor X va las filas que saltara, y el valor Y las filas que mostrara a partir de la que sigue de las que saltamos.

<br>

<div id='id7' />

# cláusula "where" para filtrar datos específicamente

Lo primero que veremos es como hacer para que nos filtre datos con precisión de lo que queremos, por ejemplo en esta cadena:

`MariaDB [Escuela]> select * from Alumnos where usuario = "dansh";`

Vemos que primero selecciona todo de la tabla **Alumnos**, para después decirle que de la columna **usuario** nos mostrara las filas que tengan el valor de "dansh" en la columna **usuario** y luego nos las muestre, por lo que se verá así:

![where1](/assets/images/SQLi/where_1.png)

Como solo hay una fila que en la columna **usuario** tenga el valor de "dansh" solo veremos 1 pero en caso de haber más nos los mostraría.

<br>

Ahora veremos la condición **!=** con **where**:

Ahora veremos lo mismo, pero inverso, ahora queremos ver las filas que NO sean igual a un valor dentro de una columna, por ejemplo, si no queremos que nos muestre las filas que en su columna **usuario** tengan de valor "dansh", haremos esto:

`MariaDB [Escuela]> select * from Alumnos where usuario != "dansh";`

Seleccionamos todo lo de la tabla **Alumnos**, después decimos que las filas de la columna usuario que NO tengan de valor "dansh" se mostraran, así que veremos todas las filas que no tengan de valor "dansh" en la columna **usuario**:

![wherenot](/assets/images/SQLi/where_not.png)

<br>

Ahora veremos la condición **or** con **where**:

`MariaDB [Escuela]> select * from Alumnos where usuario = "uriel" or id = 2;`

Esta condición nos da la opción de elegir entre una opción u otra o también ambas, por ejemplo, si queremos ver las filas que en su columna usuario contiene el valor "uriel", o si queremos ver las filas que en su columna id contenga el valor 2, entonces nos mostrará esos valores si la condición se cumple, como vemos aquí:

![or](/assets/images/SQLi/or.png)

Vemos que nos mostró las filas que contenían el valor que pusimos en la condición de acuerdo a su columna, así que vemos que nos muestra la fila que contiene "uriel" en la columna **usuario** y la fila que contiene 2 en la columna **id**.

<br>

Ahora veremos la condición **and** con **where**:

Esto a diferencia de **or**, es que los valores que le pasemos usando **and** todos tienen que ser ciertos, o sea tiene que existir lo que pedimos, ya que de lo contrario aunque falte 1 valor no nos va a mostrar nada, ya que el and depende de que todos existan para poder en este caso mostrarnos sus valores, como recordamos con el **or** aunque 1 valor existiera nos mostraba ese resultado o los que existían sin importar si algunos valores existían o no, y el and con que uno no exista ya no nos mostrara nada, ya que la condición no se cumplió.

por ejemplo:

`MariaDB [Escuela]> select * from Alumnos where usuario = "uriel" and contraseña = "URGD1414_343!!";`

Esto selecciona todo lo de la tabla **Alumnos**, para después decirle que en la columna **usuario** si su valor es "uriel", y también que la columna **contraseña** su valor es URGD1414_343!!, entonces nos va a mostrar los valores:

![and](/assets/images/SQLi/and.png)

> Recuerda que ambas condiciones deben ser ciertas para poder mostrar los valores, lógicamente deben seguir el orden de fila, por ejemplo si decimos que si en la columna de **nombre** existe una fila con valor "uriel", entonces nos la mostrara, cosa que existe por lo que pasa al siguiente valor que es and y lo que decimos es que también en la columna de **contraseña** debe haber una fila con el valor URGD1414_343!!, pero este valor deberá coincidir con la fila de la condición anterior, o sea tiene que ser de la misma fila del usuario uriel, ya que de no serlo no mostrara nada.

<br>

<div id='id8' />

# cláusula "like" para filtrar datos no específicamente

Como vimos en los ejemplos anteriores siempre teníamos que poner exacto el dato o no lo podía detectar, con la cláusula **like** podemos filtrar datos que contengan caracteres sin tener que saber el dato exacto que queremos filtrar.

`MariaDB [Escuela]> select * from Alumnos where usuario like "d%";`

Esta cadena lo que hace es seleccionar todo de la tabla **Alumnos**, para después en la columna **usuario** nos muestre las filas de la columna **usuario** que comiencen con la letra d, usando la cláusula **like**, seguido de la letra con la que queremos que nos filtre las filas que empiecen con dicha letra, y al final del lado derecho de la letra hay un % quiere decir que ese valor o sea d, filtrara en la primera letra del valor de esa fila de la columna **usuario**.

Por lo que nos mostrara en este ejemplo:

![like](/assets/images/SQLi/like_inicio.png)

Podemos ver que nos mostró de la columna **usuario** la fila que su valor iniciaba con una letra d.

<br>

Ahora para hacer lo mismo, pero en vez de que la letra se filtre por el inicio de los datos ahora se filtrara por el final de los datos, quedando la cadena así:

`MariaDB [Escuela]> select * from Alumnos where usuario like "%l";`

Ahora pusimos el signo de % del lado opuesto, ya que ahora queremos que las filas de la columna **usuario** nos muestre las filas que terminen en l.

Por ejemplo:

![likend](/assets/images/SQLi/like_fin.png)

Vemos que ahora nos filtró por las filas de la columna **usuario** que en sus filas tengan valores con una l al final, en este caso solo es 1 resultado pero si hubiese más usuarios que terminaran en la letra l obviamente se mostraría también.

<br>

Ahora aparte de filtrar una letra por el inicio o final también podemos filtrar por las filas que tengan ciertos caracteres aunque no sean exactos nos mostrara los que coincidan con esos caracteres.

`MariaDB [Escuela]> select * from Alumnos where usuario like "%e%";`

![likemedium](/assets/images/SQLi/like_medium.png)

Vemos que nos mostró las filas que contenían los caracteres que especificamos en la cadena, estas filas son de la columna **usuario**, en este caso se usan 2 signos de % y en medio los caracteres que queremos filtrar, vemos que lo que nos filtró no importo el orden mientras tuviera los caracteres que ingresamos en orden nos mostrará las filas.

> Recuerda que no solo puede ser 1 carácter como lo mostramos aquí, pueden ser palabras completas para filtrar lo deseado.

<br>

<div id='id9' />

# La instrucción UNION

Esta instrucción nos permite combinar los resultados de 2 o más instrucciones SELECT, para recuperar datos de otras tablas y así formar una sola, pero para unir 2 tablas o más en una sola primero debemos saber que deben tener el mismo tipo de dato y seguir su orden, veamos un ejemplo, recordemos que tenemos la tabla **Alumnos**, pero agregaremos otra tabla llamada **Maestros**:

![maestros](/assets/images/SQLi/maestros.png)

Vemos que los tipos de datos van en el orden y son iguales a los de la tabla **Alumnos** cuando recién la creamos, lo único que cambio fueron los nombres de las columnas, pero el tipo de dato sigue siendo el mismo!

Así que ingresamos algunos datos a la tabla **Maestros** y veremos nuestras 2 tablas, que son **Maestros** y **Alumnos**:

![2tablas](/assets/images/SQLi/2tablas.png)

Vemos que los tipos de datos para las variables de las columnas son similares, no tienen que tener el mismo tamaño de caracteres a fuerzas, pero si el mismo tipo de dato y el orden, ahora queremos unir esos datos en una sola tabla así que:

`MariaDB [Escuela]> SELECT usuario,contraseña from Alumnos UNION SELECT profesor,password from Maestros;`

Primero seleccionamos las columnas usuario y contraseña con todo y sus filas de la tabla **Alumnos**, posteriormente hicimos la unión con lo siguiente que seleccionamos, o sea las columnas profesor y password con todo y sus filas de la tabla **Maestros**, quedando así el resultado final:

![union](/assets/images/SQLi/union.png)

Vemos que respetamos el orden de las primeras columnas que seleccionamos y en base a ese orden pusimos las filas de la tabla **Maestros**, recuerda que deben estar en orden de tipo de dato y tiene que tener lógica ese orden, ya que no vas a poner una fila de contraseñas donde previamente ya habíamos asignado ese lugar para un usuario, debe respetarse eso y también tiene que ser la misma cantidad de filas que las otras, ya que de poner una de más o una de menos nos dará un error como aquí:

![error](/assets/images/SQLi/error.png)

Agregamos la columna con sus filas de **id** pero como en la siguiente seleccion no hay nada asignado para ese espacio entonces nos da este error.

Por eso debemos respetar el tipo de dato, y el orden.

<br>

<div id='id10' />

# La instrucción INSERT

Esta instrucción nos permitirá agregar filas a una tabla en respecto a sus columnas, recordemos que nuestra tabla de Alumnos por el momento esta así:

![antes](/assets/images/SQLi/antes.png)

Ahora para agregar otra fila de datos usaremos:

`insert into Alumnos (usuario,contraseña) values ("test","test123);`

Esto lo que hará es insertar en la tabla **Alumnos** datos, en este caso estos datos se agregaran en formato de filas en las columnas seleccionadas, en este caso las columnas a las que agregaremos datos son **usuario** y **contraseña**, por último agregamos los valores a las filas anteriormente seleccionadas usando **values** seguido de sus respectivos datos, y por lógica respetando el orden.

y se verá así:

![insert](/assets/images/SQLi/insert.png)

Vemos que se agregaron los datos, en la columna **id** dice NULL, ya que no asignamos nada en ese valor, pero puedes hacerlo sin problemas.

> Esto anterior ya lo habíamos visto al inicio, pero aquí lo expliqué un poco mejor.

<br>

<div id='id11' />

# La instrucción UPDATE

Esta otra instrucción nos permitirá actualizar datos de filas, por ejemplo primero como recordamos en la tabla **Alumnos** el usuario de **test** no tiene un id:

![null1](/assets/images/SQLi/null1.png)

Ahora con esta instrucción le agregaremos un id y cambiaremos sus datos:

`update Alumnos SET usuario="prueba",contraseña="prueba1525_D",id=4 where usuario="test";`

Lo que hicimos en esta cadena fue usar la instrucción UPDATE, después elegimos la tabla que deseamos actualizar, en este caso es la tabla **Alumnos**, ahora con **SET** le indicamos que asignaremos valores a estas columnas, en este caso actualizaremos la columna **usuario** y su actualización de fila será **prueba**, en la columna **contraseña** su actualización de fila será **prueba1525**, y por último la actualización de fila de la columna **id** será 4, por último ya que tenemos los valores seteados, toca decirle en que fila hará esos cambios, y estos cambios se realizaran en la fila que su columna **usuario** contenga una fila con el dato de **test**, ahí se aplicaran todos los cambios que asignemos.

Y se verá así el UPDATE:

![update](/assets/images/SQLi/update.png)

Y como vemos ya están los datos de esa fila actualizados.

<br>

<div id='id12' />

# La instrucción DELETE

Por último toca la instrucción **DELETE**, como su nombre lo dice, nos sirve para eliminar, esto nos eliminará las filas o fila que deseemos, por ejemplo de nuestra tabla **Alumnos**:

![tabla](/assets/images/SQLi/tablaAlumnos.png)

Queremos eliminar la fila que en su columna **usuario** tenga de valor "prueba", entonces hacemos:

`delete from Alumnos where usuario="prueba";`

![deleteWhere](/assets/images/SQLi/deleteWhere.png)

Y como vemos nos habrá eliminado la fila de la columna **usuario** cuyo valor era "prueba".

Siempre debes usar where, ya que de lo contrario si usas:

`delete from Alumnos;`

Esto va a eliminar toda la tabla **Alumnos**, ya que no especificamos que filas borrar ni algún límite.

<br>

<div id='id13' />

# ¿Que es SQLi?

**SQLi** es un ataque hacia un servidor de bases de datos web que consiste en ejecutar peticiones maliciosas usando la entrada de usuario, esto sucede cuando no está bien sanitizada la base de datos y podríamos aprovecharnos de esto para desplegar las bases de datos que están disponibles en el servidor web.

Ahora veremos un ejemplo:

Supongamos que entramos a la web de un blog, este blog contiene diferentes secciones, y cada sección una tiene un número único de identificación, en este caso el parámetro para diferenciar esas secciones es **id**, también cada sección tiene una configuración en forma de columna donde nos dice si esa seccion de la web esta lista para que el público la vea o aún no, supongamos que si la sección tiene un valor de 0 en la columna **private** quiere decir que esta lista, en caso de que tenga un 1 quiere decir que no esta lista.

Supongamos que nuestra tabla de esta base de datos es algo así:

![blog](/assets/images/SQLi/blog.png)

Supongamos que al entrar a una sección de la página web, en la url vemos lo siguiente:

`https://sitioweb/blog?id=1`

<br>

Como podemos ver esta en el directorio de **blog**, pero también está en la sección donde el **id** sea el valor de 1.

Por detrás en SQL esto podría verse algo así:

`select * from blog where id=1 and private=0 LIMIT 1;`

Vemos que en esta cadena esta mostrándonos los datos que hay en la sección que de **id** sea igual a 1, pero también nos está diciendo que la columna **private** de esa sección debe tener el valor 0, esto significa que debe estar listo para el público, solo así nos mostrara lo que queremos ver, también vemos que se usa el LIMIT 1 para solo mostrarnos una sección y no el resto en caso de haber más.

<br>

Esto es crítico, ya que nosotros en la url podemos ver como se está comunicando con la base de datos viendo el parámetro de **id**, así que si nosotros vamos a otra sección pero desde la url y supongamos que queremos acceder a la sección con un **id** de valor 2, pero esta sección aún no la han puesto en pública ya que tal vez aún no este lista para el público y entonces como recordamos en la url se ve así:

`https://sitioweb/blog?id=2`

y por detrás así:

`select * from blog where id=2 and private=0 LIMIT 1;`

En el **private** debe estar en 0 para mostrarnos dicha sección, pero en este caso como aún este no está listo para el público como vemos nos lo dice en la fila de la columna **private** del valor del **id** 2.

![id2](/assets/images/SQLi/id2.png)


Y como no podemos acceder nos dará error y no nos va a dejar acceder a esa sección, ya que el apartado de **private** no se cumplió, pero como dije, esto es crítico porque podría hacer esto:

`https://sitioweb/blog?id=2;--`

Ahora esto que acabamos de poner alado del id=2 en la petición de la url, como sabemos que el **;** sirve para terminar una consulta de SQL, osea que decimos que ahí debe terminar la consulta, y alado de eso vemos estos 2 guiones **- -** , lo que hace es que lo que siga del **- -** ya no se interprete y se quede como un simple comentario.

Haciendo esto nos estaríamos saltando la parte donde verifica por detrás si eso está listo o no para verse en base al valor de su **private**.

Entonces como cerramos la consulta y comentamos el resto y no se interpretara ya que lo que sigue de la consulta es un simple comentario, y esto fue gracias a que tenemos acceso a la base de datos desde el parámetro id, por lo que ejecutara la base de datos será esto:

`select * from blog where id=2;`

Y no esto:

`select * from blog where id=2 and private=0 LIMIT 1;`

Ya que como recordamos comentamos el resto que seguía de la consulta y ahora nos mostrara todos los datos del id que tenga de valor 2 y podremos ver sin consentimiento lo que hay ahí.

<br>

<div id='id14' />

# Tipos de Inyecciones SQL

**In-Band SQL Inyection** trata sobre una vulnerabilidad no tan complicada, ya que puedes explotar la vulnerabilidad desde la misma página web y ver en pantalla los resultados, existen 2 maneras la **Basada en errores** y **Basada en unión**.

<br>

# Inyección Basada en errores

La inyección SQL **Basada en errores** nos es más útil y rápida para obtener información de como está estructurada la base de datos que corre en la página web, esto nos puede servir para ir enumerando la base de datos conforme a los resultados y podríamos extraer información importante de la **estructura** de la base de datos.

# Inyección Basada en unión

Esta inyección **Basada en unión**, nos es útil para poder extraer datos usando el operador de SQL **UNION** junto con la declaración **SELECT** para devolver grandes cantidades de datos dentro de la base de datos.

<br>

<div id='id15' />

# Prueba de inyección Basada en errores (practica en Acuentix)

Para practicar esta inyección usaremos la página web:

[web vulnerable](http://testphp.vulnweb.com)

Al abrir esta página web vulnerable para pruebas veremos que nos carga el inicio, y arriba en la sección de **Categories** iremos a la que dice posters por ejemplo:

![posters](/assets/images/SQLi/posters.png)

Ahora entramos y vemos unos posters en la página web, pero también aparte de esos posters en la url vemos que hay un parámetro en este caso se llama **cat** y de valor tiene 1, o sea que puede que se comunique con la base de datos mostrándonos el contenido que hay en el valor 1, en este caso estos posters.

![cat](/assets/images/SQLi/cat.png)

Ahora intentaremos romper esta consulta hacia la base de datos usando una comilla, ¿Porque esto?, Es porque por ejemplo la consulta actual en la url es:

`http://testphp.vulnweb.com/listproducts.php?cat=1`

y por detras en el **DBMS** se veria algo así:

`consulta = "select * from listproducts where ProductID = " + Request["1"];`

Supongamos que está haciendo una consulta la cual selecciona todo de la tabla **listproducts** y nos mostrara el apartado donde el id en la respuesta sea igual a 1, o sea en el apartado de la web que estamos, pero hacerlo de esta forma es peligroso, ya que nosotros como usuarios de la web podemos ver la petición que es 1, y como la web se va cambiando automáticamente de id porque es lógico al cambiar de sección, en este caso estamos en el 1 que es el apartado de **posters**.

<br>

Pero volviendo a lo que comente sobre usar una comilla, esto lo hacemos para romper la consulta y esto nos servirá para lo siguiente, primero en la url agregaremos una comilla simple o doble como sea, el caso es ponerla al final del id:

`http://testphp.vulnweb.com/listproducts.php?cat=1'`

Esto en el **DBMS** se interpretara así:

`consulta = "select * from listproducts where ProductID = " + Request["1'"];`

Y como vemos en la petición del id se agregó una ´ lo cual esto confundirá al **DBMS**, haciendo que nos muestre un error de consulta como este:


![comilla](/assets/images/SQLi/comilla.png)

Como vemos ya no nos muestra lo que había en el id 1, que eran los posters, en lugar de eso nos muestra un error de sintaxis porque estaba leyendo desde peticiones web para responder al servidor de bases de datos, pero como las consultas en este caso se hacen desde la url, cosa que no debe hacerse en un entorno real o será vulnerable a sqli, volviendo a lo que decía, vemos que se hace la petición directa de la url por lo que al mostrarnos este error estamos consientes de que ejecuta las consultas desde la url y nos indica que hay una vulnerabilidad de SQL basada en errores, ya que hemos roto la consulta, pero en vez de romperla podriamos empezar a agregar nuestras consultas desde la url y el DBMS nos lo va a interpretar, ya que se pasa directo de la url al DBMS cosa que como dije no debe hacerse o tendrás tu sitio vulnerable.

<br>

Ahora lo que sigue sabiendo que el sitio es vulnerable a SQL basado en errores, es intentar que nos cargue el sitio web correcto sin errores en el apartado posters como lo estamos haciendo en este ejemplo, así que usando el operador **order by**.

Esto nos servirá para ir descubriendo cuantas tablas nos está regresando sql hacia el servidor web, esto nos interesa para algo que veremos más adelante, primero hay que descubrir cuantas tablas nos está devolviendo, así que para saber cuantas, primero debemos hacer el **order by** y pasarle un valor aproximado, así que para empezar pondremos 50, en la url se verá así:

![50](/assets/images/SQLi/50.png)

En la url vemos que pusimos:

`http://testphp.vulnweb.com/listproducts.php?cat=1 order by 50`

Y como vemos en la imagen, nos da un error, ya que nos hemos pasado de las columnas disponibles, por lo que probaremos con un número más bajo:

![10](/assets/images/SQLi/10.png)

Como vemos en la url ahora pusimos 10 y como esta cantidad es menor que las columnas que hay nos carga el contenido sin errores, ahora debemos ir subiendo poco a poco hasta llegar al que sepamos que es el límite, en este caso tras intentar descubrí que el límite de columnas era 11, ya que si era 12 nos daba error porque se pasaba así que ahora sabemos cuantas columnas nos devuelve sql en esta página web

![11](/assets/images/SQLi/11.png)

Como vemos en la url sabemos que el límite es 11 columnas, pero aparte vemos 2 guiones como se ve en la imagen, estos guiones:

`http://testphp.vulnweb.com/listproducts.php?cat=1 order by 11 --`

Vemos que hay **--** esto nos sirve para indicarle que el resto de la consulta se convierta en comentario y no se interprete, haciendo que solo se ejecute lo del inicio hasta donde esta dicho comentario, por ejemplo, supongamos que hemos encontrado una web vulnerable, y hacemos una petición a la base de datos desde la url porque encontramos una vulnerabilidad de inyección sql, y la consulta desde la url se verá así por ejemplo:

`http://testphp.vulnweb.com/listproducts.php?cat=1 order by 11 --`

Y la consulta por detrás algo así:

`consulta = "select * from listproducts where ProductID = " + Request["1 order by 11 --"] and ALGUN_FILTRO..... ;`

Supongamos que en la consulta está lo que intuimos que hay, pero más allá de la petición request no sabemos que filtros pueden haber y si no se cumplen nos dará error arruinándonos la inyección, pues los **--** nos sirven para comentar el resto que sigue de la petición, así evitarnos posibles filtros y poder ejecutar correctamente la inyección.

Ya que de lo contrario si no lo hubiésemos comentado nos daría algún error, ya que podría haber algún filtro y esto gracias a que en el AND de la consulta nos extiende la petición, pero como dije, con los guiones podemos omitir el resto y saltarnos posibles filtros.

<br>

Aclarando eso, volveremos a la web, recordamos que sabemos el número de columnas exactas devueltas, en este caso 11, por lo que ahora debemos saber en qué parte de la página web se adaptan esas columnas y ver si algunas son visibles para sacar provecho de que las podemos ver como veremos a continuación.

Pero antes de eso debemos saber en qué parte de la web están esas columnas, por lo que aquí entra la parte de **UNION SELECT**.

Primero aquí vemos esto:

![union select](/assets/images/SQLi/union_select.png)

Primero vemos que el parámetro **cat** que habíamos mencionado antes ya no es 1, ya que de lo contrario si seguiría siendo 1 nos mostraría lo que hay en el valor 1 de la tabla correspondiente que serian seguramente las secciones de los **posters** como habíamos visto, pero como nosotros no queremos ver eso como primera opción, lo que hice fue cambiar ese 1 por 0 para que nos muestre lo que queremos y no el contenido real, también podríamos agregar un -1 o un **NULL**, haciendo esa parte inválida y dejándonos vacío para lo siguiente que queremos hacer.

Ahora alado como vemos aparece:

`http://testphp.vulnweb.com/listproducts.php?cat=0 union select 1,2,3,4,5,6,7,8,9,10,11 --`

Vemos que usamos el operador **UNION** junto con la declaracion **SELECT**, como sabemos esto nos sirve para ordenar distintas columnas que hay en uso en una sola y así ver lo que se ve en la imagen, vemos que en la imagen anterior ya no nos mostró el apartado de posts, si no lo que queremos ver, y cambiaron de lugar las columnas por la enumeración que le dimos para identificarlas fácilmente, en este caso vemos que las que se ven a simple vista son la 11, 7, 2 y 9, ahora lo que podríamos hacer es que en el campo de esas columnas podríamos hacer peticiones más interesantes que nos interprete el **DBMS** y poder poco a poco enumerar la base de datos y los **--** ya sabemos para qué son.

<br>

Un ejemplo de que podríamos hacer teniendo a nuestra vista las columnas es lo siguiente:

![version](/assets/images/SQLi/version.png)

Vemos en la url:

`http://testphp.vulnweb.com/listproducts.php?cat=0 union select 1,2,3,4,5,6,@@version,8,9,10,11 --`

Que en el lugar del número 7 establecimos el comando @@version, que esto si lo interpreta Sql nos da la versión que corre la base de datos, y como en la imagen vemos en vez del lugar del número 7 nos muestra la versión actual, en este caso es:

`8.0.22-0ubuntu0.20.04.2`

> Aparte de **@@version** también exiten otros como **@@user**, etc.

De la misma manera podríamos saber otras cosas como por ejemplo ver la base de datos actual:

![database](/assets/images/SQLi/database.png)

Vemos que ahora la url es:

`http://testphp.vulnweb.com/listproducts.php?cat=0 union select 1,2,3,4,5,6,database(),8,9,10,11 --`

Que esa es la función que nos devuelve la base de datos actual en uso que en este caso se llama **acuart** como vemos en la respuesta de la consulta.

<br>

Ahora seguiremos probando cosas, pero esta vez usando una máquina de una sala de try hack me que es la siguiente:

[TryHackMe](https://tryhackme.com/room/sqlinjectionlm)

<br>

Al entrar a la página web de la sala, veremos esto con un primer nivel de prueba:

![inicio](/assets/images/SQLi/inicio_sala.png)

Primero intentaremos romper la consulta SQL, como recordamos esto se hace usando una comilla simple o doble:

![error_consulta](/assets/images/SQLi/error_consulta.png)

Vemos que nos muestra el error de la consulta rota, por lo que esto nos indica que puede ser vulnerable, ya que está interpretando directamente desde la url hacia el DBMS.

<br>

<div id='id16' />

# Inyección SQL Basada en errores (Prueba en TryHackMe)

Ahora trataremos de descubrir cuantas columnas se están devolviendo hacia el servidor web, usando el **order by** para ordenar las posibles columnas que hay detrás.

Intentamos primero con 4 y nos da este error:

![order4](/assets/images/SQLi/orderby4.png)

Por lo que intuimos que podría ser menos, ya que en la web no se ven muchos datos por lo que pusimos ahora 3:

![order3](/assets/images/SQLi/orderby3.png)

Y ahora nos cargó el contenido sin error!, por lo que la cantidad de columnas devueltas a esa parte de la web es 3.

<br>

Ahora sigue saber en qué parte de la web se están devolviendo esas columnas, por lo que para ver su posición en la ruta actual de la web haremos lo siguiente:

`https://website.thm/article?id=0 union select 1,2,3 --`

> No olvidemos comentar el resto de la consulta para evitar errores de la consulta que puede seguir de nuestras instrucciones.

Primero, como sabemos el parámetro **id** de la página web es la que en este caso señala en que ruta de la web estamos, por defecto era 1, ya que en el DBMS el del id 1 era el artículo que se nos debía mostrar por defecto, pero en este caso ponemos un 0 para invalidar esa consulta y nos muestre otra cosa, en este caso queremos unir las tablas seleccionadas en este caso la 1,2 y 3. Que son la cantidad de columnas que sabemos que hay en esa sección de la web.

![union](/assets/images/SQLi/unionselect.png)

<br> 

Como vemos nos está mostrando en que parte esta cada columna identificadas por el nombre que les pusimos en este caso números ascendentes, así que sabiendo esto podremos pasar a lo siguiente.

 > En este caso en el **id** invalidamos la petición por defecto por un valor no registrado, en este caso 0, por lo que se marca como nulo y pasa a mostrarnos lo que sigue de la consulta que construimos, en este caso los números para identificar las columnas en su lugar, y no la página por defecto que sería **id=1**, pero en caso de que el **id** contenga caracteres se puede invalidar usando **NULL**.

<br>

Ahora ya que sabemos donde se está devolviendo cada columna, lo que haremos es reemplazar lo que se tiene que mostrar, por algo de nuestro interés, veremos lo que nos interesa en lugar de lo que esas columnas muestran por defecto, así que lo primero que haremos es cambiar un valor de la consulta que habíamos generado anteriormente, recordamos que esta así:

`https://website.thm/article?id=0 union select 1,2,3 --`

Pero ahora lo que cambiara es que en lugar del 2, pondremos una función de sql que nos devolverá el nombre de la base de datos actual:

`https://website.thm/article?id=0 union select 1,database(),3 --`

Ahora vemos que en el lugar de la columna que asignamos la etiqueta número 2, la cambiamos por una función, la cual nos devuelve el nombre de la base de datos, por lo que al tramitar esta consulta se nos verá reflejada de la siguiente manera:

![database](/assets/images/SQLi/databasee.png)

<br>

Vemos que la base de datos en uso se llama **sqli_one**, por lo que ya tenemos algo con lo que empezar!

Lo siguiente es ver todas las bases de datos disponibles en el servidor y no solo la que está en uso, para eso agregaremos las siguientes instrucciones a la consulta desde la url:

`https://website.thm/article?id=0 union select 1,schema_name,3 from information_schema.schemata limit 1-- -`

Aqui le estamos indicando en el valor del **2** que nos da el nombre de esquema con **schema_name**, de la base de datos **information_schema.schemata**, y después nos limitara a ver la primera fila del resultado.

> Esta base de datos es accesible por todos los usuarios y dentro de esta base de datos contiene información sobre las bases de datos y sus respectivas tablas.

Quedándonos así:

![schema_name](/assets/images/SQLi/schema_name.png)

Esto es lo que hay en la primera fila, pero iremos modificando el **limit**, para ver más nombres de bases de datos:

`https://website.thm/article?id=0 union select 1,schema_name,3 from information_schema.schemata limit 1,1-- -`

Ahora le decimos que nos muestre lo que hay 1 fila después de la primera, y nos mostrara esto:

![sql_one](/assets/images/SQLi/sql_one.png)

Vemos que esta está base de datos llamada **sqli_one** es la que ya habíamos descubierto antes, así que sabemos que por ahora hay 2 bases de datos, intente aumentar el limit, pero ya no había, ya que solo hay 2 bases de datos en este servidor web, así que de las 2 bases de datos usaremos la que se llama **sqli_one**, ya que la otra es la que usamos para poder enumerar estas bases de datos.

<br>

Ahora como dijimos vamos a  listar las tablas de la base de datos que nos interesa en este caso **sqli_one**, como ya sabemos el nombre de la base de datos lo que haremos es:

`https://website.thm/article?id=0 union select 1,table_name,3 from information_schema.tables where table_schema = "sqli_one" limit 1,1-- -`

Ahora lo que hicimos fue cambiar el valor donde se supone que va el valor de la etiqueta en la columna 2, por el valor de **table_name**, que anteriormente era **schema_name**, pero como ya sabemos la base de datos y ahora queremos sacar las tablas de esa base de datos hacemos eso, y por último le indicamos que queremos que nos muestre las tablas cambiando el **information_schema.schemata** Por **information_schema.tables**, ya que queremos las tablas de la base de datos la cual está en el valor del parámetro **table_schema** que en este caso su valor es como sabemos **sqli_one**.

<br>

Y al final usamos limit para ir viendo de una por una, sé ve algo así:

Aqui vemos lo que hay despues de la primera tabla (limit 1,1):

![table_name](/assets/images/SQLi/table_name.png)

Y aqui vemos lo que hay en la primera tabla (limit 1 recuerda que cuando se pone solo el 1, sin más números, solo te muestra el primer resultado):

![table_name1](/assets/images/SQLi/table_name1.png)

<br>

Buscando más tablas no encontré, ya que solo hay 2:

- **staff_users**
- **article**

Entonces la que más llama la atención es la de **staff_users**, Ya que su nombre dice que contiene usuarios, por lo que iremos a por esa tabla.

<br>

Ahora intentaremos listar los datos de esa tabla, o sea que listaremos las columnas de esa tabla:

`https://website.thm/article?id=0 union select 1,column_name,3 from information_schema.columns where table_schema = "sqli_one" and table_name = "staff_users" limit 1-- -`

Aquí lo que hicimos fue que reemplazamos el valor de **table_name** por **column_name**, ya que ya sabemos el nombre de la tabla y ahora trabajaremos en mostrar una columna, y ahora cambiaremos **information_schema.tables** por **information_schema.columns**, esto lo que hará es mostrarnos las columnas de una tabla que se encuentra en la base de datos **sqli_one**, Y esa tabla se llama **staff_users** por lo que le agregamos ese valor usando el **and table_name**, por último le decimos que nos muestre la primera columna de la tabla **staff_users** y el resultado es así:

![staff_users](/assets/images/SQLi/staff_users.png)

<br>

Vemos que la primera columna se llama **id**, para encontrar más podríamos jugar con el limit, pero hay una función llamada **group_concat()** que nos permite concatenar todos los datos en una sola consulta para así evitar perder tiempo con el **limit**, puedes usar el **limit** en caso de que el **group_concat()** no te funcione, pero en este caso lo usamos y:

`https://website.thm/article?id=0 union select 1,group_concat(column_name),3 from information_schema.columns where table_schema = "sqli_one" and table_name = "staff_users"-- -`

![group_concat](/assets/images/SQLi/group_concat.png)

Y como vemos nos muestra las columnas de la tabla concatenadas sin tener que perder tiempo una por una con el limit.

En este caso son 3 columnas:

- **id**
- **username**
- **password**

<br>

Ahora ya solo queda mostrar los datos de esas columnas de la tabla **staff_users**, en la base de datos **sqli_one**.

> Hay ocasiones donde una base de datos usa de "proteccion" que no acepte consultas en texto claro, si no en hexadecimal, pero esto se puede evadir enviando la consulta en hexadecimal en lugar de texto.

Volviendo a lo que estaba explicando de mostrar los datos de esas columnas, ya que sabemos la base de datos, la tabla, y las columnas que nos interesan solo queda mostrarlas, como se ve aquí:

`https://website.thm/article?id=0 union select 1,group_concat(username,':',password),3 from sqli_one.staff_users -- -`

![group_concat1](/assets/images/SQLi/group_concat1.png)

Solo concatenamos los nombres de las columnas que nos interesan y en medio agregamos dos puntos para separar el usuario de la contraseña en cada fila que recorra cada columna, y por último le decimos que todo eso lo sacara de la base de datos **sqli_one** en la tabla **staff_users**.

Y ya veremos las credenciales que buscamos.

> La función **group_concat()** puede servir en cualquier caso para agrupar datos y pudo haberse utilizado al principio pero no se uso para mostrar como funcionaba el limit y después este o sea **group_concat()**, eliges el que más te sirva y te guste.

<br>

<div id='id17' />

# Bypass de autenticación (BLIND SQLi)


Ahora pasamos al Nivel 2 de este desafío, el cual es bypassear un panel de login, esto significa que por así decirlo saltarnos el paso y entrar al sistema sin logearnos, y lo de **BLIND SQLi** significa sqli a ciegas, es decir, como anteriormente vimos en el nivel anterior fuimos avanzando a medida de prueba y error para crear la url indicada para enumerar la base de datos, pero en este caso no nos va a mostrar nada o muy poco de información y será difícil saber si la inyección se ejecutó con éxito o no, pero a pesar de esto, si se hace correctamente puede funcionar la inyección, el nivel 2 se ve así:

![level2](/assets/images/SQLi/level2.png)

<br>

Nos pide un usuario y una contraseña, lo que queremos es saltarnos este paso, en este caso nos interesa más pasar el panel del login que enumerar la base de datos, pero antes de esto hay que saber unas cosas importantes y bases para entender esto.

Como leemos en la imagen abajo en la parte izquierda está la siguiente consulta que es como funciona el servidor web, en este caso:

`select * from users where username='%username%' and password='%password%' LIMIT 1;`

Vemos que la base de datos se comunica con la web en el panel login, lo que hace es seleccionar todo lo de la tabla **users**, después pregunta si el parametro **username** y el parámetro **password** son verdaderos entonces si eso se cumple se tomara como **true**, y esto se valida usando los **%username%** que se comunican directamente con el panel login del servidor web, esto obtiene el contenido que hay dentro de los recuadros donde ingresas los datos, igual sucede con **%password%**, y si pones datos correctos, entonces la consulta sql verificara si esos datos ingresados coinciden con alguno de la tabla **users**, y en caso de que si exista nos deja entrar, ya que esto se tomó como verdadero.

<br>

Como sabemos, en teoria si la contraseña y usuario son correctos entonces la consulta sql se tomara como **true** y nos dejara entrar al sistema, caso contrario se tomara como **false**, ya que los datos no coinciden con los de la tabla **users**, así que sabemos que la validación final es si es **true** o **false**, y si es **true** nos deja entrar, si es **false** no nos dejara entrar, pero si un login usa este método de autenticación sin sanitización de la entrada de datos, entonces podremos inyectar directamente consultas sql y alterar el resultado final.

<br>

Lo que haremos ahora es tratar de modificar esa consulta final, sabemos que la original por detrás es:

`select * from users where username='%username%' and password='%password%' LIMIT 1;`

Pero en el recuadro de usuario o password, podríamos hacer esto:

![bypasslogin](/assets/images/SQLi/bypasslogin.png)

Vemos que el servidor web no estaba sanitizado para evitar estas inyecciones, y lo que hicimos fue modificar la consulta quedándonos así la consulta final:

`select * from users where username='' OR 1=1; -- -' and password='%password%' LIMIT 1;`

Lo que paso aquí fue que el servidor web no sanitizo la entrada de datos y se pueden pasar como consultas, primero con la comilla rompemos la primera parte de la consulta, pero agregamos el operador **OR** y algún valor que sea **true** o sea que mientras se cumpla se tomara como verdadero, en este caso decimos que si 1 es igual a 1, esto lógicamente es si o sea que como agregamos el **OR** esto nos permitirá que si la primera parte de la consulta es falsa, pero la segunda verdadera entonces mientras una de las 2 partes sea verdadera toda la respuesta será **true** y al final ponemos los **;** para terminar la consulta sql, y comentando todo el resto que era la parte de **password** para evitar problemas, asi que lo que hicimos que saltarnos el **and**, ya que fue comentado y con el **OR** logramos una validación dándonos como resultado **true** y dejándonos entrar al sistema.

aquí vemos un ejemplo de la consulta:

![comentado](/assets/images/SQLi/comentado.png)

Vemos que desde que comentamos el resto de la consulta se torna color gris, ya que nos indica que eso no se tomara en cuenta y solo lo que está en negro.

<br>

Así que al tramitar esta petición vemos que nos deja acceder al sistema:

![entrada](/assets/images/SQLi/entrada.png)

Vemos que sigue el nivel 3!.

<br>

<div id='id18' />

# Basado en Booleanos (Blind SQLi)

Como recordamos, Blind SQLi es un ataque del cual no puedes ver mucha información y debes trabajar más a ciegas, esta es la contraria de la basada en errores que como recordamos nos mostraba todo en pantalla, este ataque llamado **Basado en booleanos** se le denomina así, ya que como sabemos un booleano en programación es algo que solo tiene dos posibles respuestas ante una consulta, por ejemplo, los más comunes son las respuestas **true** y **false**, son un tipo de dato que solo tiene 2 respuestas, y con base en esto sabremos si nuestra consulta de sqli fue exitosa o no.

> Aunque esto parezca muy imposible de enumerar una base de datos con estas limitaciones es posible y veremos como.

<br>

![boolean](/assets/images/SQLi/basedboolean.png)

<br>

Vemos en la imagen que nos muestra el panel login en el que debemos hacer la inyección basada en booleanos.

`https://website.thm/checkuser?username=admin`

La URL se ve así, ya que le estamos dando en el campo de username el valor de **admin**.

Pero también vemos arriba la respuesta de una función que se encuentra en muchos formularios de login, es una parte de una API que nos muestra con **true** o **false** si un usuario ya está registrado o no, en la imagen se ve el valor **true** por lo que un usuario llamado **admin** ya existe, así que si cambiamos ese nombre por otro por ejemplo **admin5**, veremos que se torna **false** la respuesta de esa función:

![false](/assets/images/SQLi/false.png)

Vemos que en la consulta se ve así:

`select * from users where username = '%username%' LIMIT 1;`

Recordemos que el **%username%** en este caso es el campo de **username** que se ve en el panel login y estos porcentajes indican que de esa parte del panel login obtendrá el valor deseado para la consulta.

<br>

Ahora queremos enumerar la base de datos, y como el primer paso es saber la cantidad de columnas dentro de la página web haremos esto, manteniendo el usuario **admin5** hacemos la siguiente consulta en la url:

![false1](/assets/images/SQLi/false1.png)

<br>

`https://website.thm/checkuser?username=admin5' UNION SELECT 1,2; --`

Vemos que hicimos algo parecido a lo que hicimos con bases de datos anteriores, cerramos con una comilla la parte donde nos pide ingresar el usuario que en este caso es admin5, despues procedemos a inyectar la consulta **UNION SELECT** para que nos junte las columnas en un solo lugar y después de esto vemos que la respuesta es **false**, ya que no es la cantidad correcta de columnas devueltas, y no usamos el **order by**, ya que en este caso no nos detectó usar el order by.

<br>

Pero como vemos en la respuesta es **false** por lo que podemos saber que esa no es la cantidad correcta de columnas devueltas, así que agregaremos valores hasta que sea el valor correcto, por lo que iremos aumentando hasta obtener un **true**:

![true](/assets/images/SQLi/true.png)

`https://website.thm/checkuser?username=admin5' UNION SELECT 1,2,3; --`

Vemos que ahora esta es la cantidad correcta de columnas devueltas, ya que nos devuelve un **true**!

<br>

Así que ya sabemos la cantidad de columnas devueltas, 3.

<br>

Ahora enumeraremos el nombre de la base de datos en uso, recordemos que podemos usar, **database()** para saber la base de datos en uso, pero como esta es una Blind SQLi, no nos mostrara nada, por lo que cambiaremos el modo, como recordamos usando la cláusula **like** y sus parámetros de porcentaje, podríamos decirle que nos mostrara aquello que empezara, terminara o contenga un carácter de un nombre de lo que se le haya indicado, en este caso, lo usaremos para ir probando letra por letra y con base en la respuesta de la función de valores booleanos ir formando lo que queremos ver.

<br>

Empezamos:

`https://website.thm/checkuser?username=admin5' UNION SELECT 1,2,3 where database() LIKE 's%'; --`

Aquí iniciamos diciéndole en base a **database()** y la cláusula **LIKE** que nos muestre lo que empiece con la letra "s", y como esta función de **database()** solo nos devuelve la base de datos actual, entonces solo habrá una posible respuesta y nos la mostraría, pero como esto es blind no veremos nada, pero en el valor de **true o false** podremos ver si por detras nos mostró algo o no, en este caso el valor es **true** por lo que la base de datos actual inicia con la letra "s", de lo contrario nos daría false, ya que no inicia con esa letra.

![lt](/assets/images/SQLi/liketrue.png)

<br>

Así que ya tenemos la letra con la que empieza la base de datos, y en este punto es de intentar con cada carácter hasta descubrir el nombre completo de la base de datos:

![sq](/assets/images/SQLi/sq.png)

<br>

Vemos que la siguiente letra del nombre de la base de datos es "q", así que ya una vez hayamos descubierto el nombre entero que en este caso es, **sqli_three**, procederemos a enumerar las tablas de esta base de datos.

<br>

Anteriormente para enumerar las tablas de una base de datos podría hacerse así:

`admin5' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema = 'sqli_three';--`

Esto funcionaria si este nivel fuera basado en errores, pero como es blind, esto no nos va a funcionar, ya que lo que hacía la basada en errores era mostrarnos en el campo del número 2, la respuesta de nuestras consultas que era obtener las tablas **FROM information_schema.tables** de la base de datos **WHERE table_schema** con el nombre de **sqli_three**, pero, como en este caso no podemos ver nada de esta consulta, tendrá que cambiar la manera en que lo hacíamos.

> Algo que no explique en sqli basada en errores es que si quieres enumerar las tablas o columnas de la base de datos actual, no es necesario indicarle en que base de datos ejecutara las consultas, ya que tomara la actual como la primera, y así te ahorras tiempo.
Así que si quisiéramos en este ejemplo mostrar las tablas de la base de datos actual podría hacerse simplemente así:
`admin5' UNION SELECT 1,table_name,3 FROM information_schema.tables;--` al igual que con una columna.

<br>

Volviendo al blind sqli, Ahora en vez de mostrar los resultados en un campo del lugar de una tabla con etiqueta como lo hacíamos en la basada en errores, lo haremos sin ella, así:

`admin5' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--`

<br>

Esta consulta es algo parecido a lo que hicimos con lo que descubrimos el nombre de la base de datos jugando con **database()** y **LIKE**, pero en este caso como queremos saber las tablas jugaremos con **table_name** y **LIKE**, empezamos indicándole que si hay alguna tabla que empiece con la letra "a".

En este caso nos responde con esto:

![falsee](/assets/images/SQLi/falsee.png)

Responde con un **false**, ya que ninguna tabla inicia con esa letra, por lo que seguiremos probando!

<br>

Seguimos intentando hasta que encontré que la base de datos comienza con la letra u:

![u](/assets/images/SQLi/u.png)

Como vemos aquí arriba.

<br>

Después de descubrir cada carácter descubrí que el nombre de la tabla es **users**:

`admin5' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'users%';--`

<br>

Ya tenemos la base de datos, la tabla y ahora nos interesa enumerar las columnas de esas tablas!.

> Es lógico que existan más tablas y por eso puedes tardar más en enumerar hasta que alguna sea de tu interés, en este caso la tabla que nos interesa es **users**.

<br>

Ahora haremos el mismo método, pero esta vez lo haremos con las columnas de la tabla **users** de la base de datos **sqli_three**, vemos que agregamos un AND para el nombre de la columna que queremos descubrir, como sabemos jugando con la cláusula **LIKE**:

`admin5' UNION SELECT 1,2,3 FROM information_schema.columns WHERE table_schema = 'sqli_three' and table_name = 'users' and column_name like 'i%';--`

<br>

Primero le indicamos que si hay una columna que comience con la letra "i":

![i](/assets/images/SQLi/i.png)

<br>

Y como apreciamos en la imagen existe una columna que comienza con la letra "i", por lo que al seguir intentando más caracteres descubrí que era la columna **id**.

<br>

Después de investigar a fondo con múltiples caracteres descubrí 3 columnas en total:

- **id**
- **user**
- **password**

<br>

Ahora, las columnas que llaman nuestra atención son **user** y **password**, por lo que como sabemos haremos el mismo método pero esta vez con esas columnas:

`admin5' UNION SELECT 1,2,3 FROM sqli_three.users WHERE username LIKE 'a%';--`

Lo que hicimos en esta consulta nueva fue que ahora como ya tenemos el nombre de la base de datos, de la tabla, y de la columna, y ya solo queda saber los datos de dicha columna que nos interesa, entonces le decimos que queremos datos de(FROM) donde la base de datos se llame **sqli_three** y ahora les mostraré algo que no había explicado, y es que al poner el nombre de la base de datos y seguido separado por un punto, el nombre de la tabla que nos interesa, entonces estamos sacando datos de la tabla **users** de la ya dicha base de datos, y por último le decimos que exactamente(WHERE) queremos de la columna **username** lo que inicie en este caso con la letra "a" como ya sabemos jugando con LIKE.

<br>

En este caso el valor nos regresa **true**:

![a](/assets/images/SQLi/a.png)

Y como sabemos es señal de que hay datos dentro de la columna **username** que comienzan con la letra "a", por lo que al seguir enumerando encontramos el usuario **admin**.

<br>

Al encontrar un usuario que por lógica de su nombre es importante entonces nos quedaremos con este usuario **admin** y ahora enumeraremos lo que hay en la columna **password** del usuario **admin**:

`admin5' UNION SELECT 1,2,3 FROM sqli_three.users WHERE username = 'admin' AND password LIKE '3%' ;--`

> Recuerda que filtramos solamente el valor de la columna **password** perteneciente al usuario **admin**, porque en la consulta le indicamos con condicionales que queremos exactamente ese valor, y no se mezcle con otras posibles contraseñas de otros usuarios, ya que le estamos diciendo que donde el username sea **admin** nos mostrara su valor de password, y solo queda ver ese valor jugando con like.

Volviendo a la enumeración de la columna **password**, me di cuenta de que el dígito 3 retornaba true, por lo que la contraseña debe empezar con el dígito 3, ahora como sabemos seguimos enumerando hasta que dimos con la password del usuario **admin**:

![3](/assets/images/SQLi/3.png)

<br>

Como sabemos debemos seguir con los caracteres siguientes hasta descubrir el valor, en este caso el valor final era **3845**, por lo que esa es la contraseña del usuario admin!.

<br>

Como resolvimos esto hemos pasado al penúltimo nivel de esta sala.

Comencemos con el siguiente nivel!

<br>

<div id='id19' />

# Basado en Tiempo (Blind SQLi)

Este método igual es Blind, por lo que no veremos alguna respuesta del servidor, sin embargo podremos saber usando un método integrado llamado **SLEEP(X)**, este método nos servirá para decirle que tarde X segundos y después nos da el resultado, para entenderlo veamos un ejemplo:

En este caso detectamos la vulnerabilidad en el panel login, similar al anterior:

![nivel4](/assets/images/SQLi/nivel4.png)

<br>

En este caso vemos la primera url donde está la vulnerabilidad y después el otro panel que es el login, y en medio hay un reloj que nos ayudara a  guiarnos cuanto tarda en responder cada consulta!

Como vemos en la url:

`https://website.thm/analytics?referrer=tryhackme.com`

Esta por defecto el usuario tryhackme.com, pero nosotros haremos la inyección usando la ya conocida comilla para escapar del parámetro por defecto en este caso es **referrer**, y poder asignarnos a la consulta, por lo que pondremos lo siguiente:

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5); --`

Como vemos agregamos el método SLEEP diciendo que espere 5 segundos, pero esto solo esperara X cantidad de tiempo siempre y cuando la consulta que hagamos se torne como verdadera **true**, pero en este caso:

![time1](/assets/images/SQLi/time1.png)

Vemos que solo tardo menos de 1 segundo para interpretar esta consulta, por lo que sabemos significa que no tuvo éxito en este caso **false**.

Así que intentaremos agregar más etiquetas para detectar el número de tablas devueltas:

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2; --`

Como vemos agregamos una etiqueta para la siguiente columna, en este caso en total hay 2 columnas, la primera no tiene etiqueta, pero si el método SLEEP que cuenta como una etiqueta, por eso agregamos el 2 al siguiente valor de columna, realmente no afecta el nombre de etiqueta, pero es para ordenar más tu consulta.

Y la respuesta del tiempo será algo así:

![time5](/assets/images/SQLi/time5.png)

<br>

Vemos que tardo 5 segundos en responder!, lo cual significa que esta consulta tuvo éxito, y ya sabemos el total de columnas devueltas, 2.

<br>

Lo que sigue es enumerar la base de datos en uso si es que nos interesa, por lo que similar a la inyección anterior, jugaremos con la cláusula LIKE:

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'a%' ; --`

Como vemos ahora queremos saber el valor donde la base de datos actual comience con la letra "a":

![LIKEa](/assets/images/SQLi/LIKEa.png)

Vemos que nos responde que tardo menos de 1 segundo, por lo que sabemos que esta respuesta es false y no comienza con la letra "a".

<br>

Después al probar la siguiente letra "s", tardo 5 segundos en responder, por lo que es una señal de que devolvió un valor **true** esa consulta, y al seguir intentando el nombre de esa base de datos que descubrimos por intentos es **sqli_four**, como vemos en la siguiente consulta:

![sqli_four](/assets/images/SQLi/sqli_four.png)

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'sqli_four%' ; --`

<br>

Ahora procederemos a crear las consultas para enumerar nombres de tablas dentro de esta base de datos:

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 FROM information_schema.tables WHERE table_schema = 'sqli_four' AND table_name LIKE 'a%' ; --`

En esta consulta ahora agregamos el **information_schema.tables**, para obtener información sobre las tablas en la base de datos **sqli_four**, y esa información se filtrará donde también el nombre de una tabla **table_name** empiece con la letra "a".

En este caso el servidor web nos responde que tardo 5 segundos!, lo cual significa que esto es **true**:

![5s](/assets/images/SQLi/5s.png)

<br>

Vemos que hay una o también varias tablas que pueden iniciar con la letra "a", así que como sabemos iremos repitiendo el método de descubrir los nombres por medio de la cláusula LIKE.

<br>

Una vez enumeremos los nombres de las tablas que encontramos, en este caso encontré:

- **analytics_referrers**
- **users**

<br>

![users123](/assets/images/SQLi/users123.png)

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 FROM information_schema.tables WHERE table_schema = 'sqli_four' AND table_name LIKE 'users%' ; --`

<br>

Como vemos hemos encontrado 2 tablas dentro de esta base de datos, ahora debemos sacar las columnas de la tabla que nos interesa, en este caso **users** nos llama más la atención, por lo que procederemos a buscar sus columnas:

![like_a](/assets/images/SQLi/like_a.png)

<br>

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 FROM information_schema.columns WHERE table_schema = 'sqli_four' AND table_name = 'users' AND column_name LIKE 'a%' ; --`

> Para recordar, cuando usamos **FROM** es de donde vamos a obtener lo que queremos en este caso de **information_schema.columns** y **WHERE** son las condiciones para mostrar lo que queremos específicamente, como filtrar datos de la tabla **users** especificamente datos de ahí y no de otra, y cuando usamos **AND** eso que sigue del AND sigue siendo parte del **WHERE**.

<br>

Vemos que ya que tenemos el nombre de la tabla que nos interesa, entonces cambiamos lo de **information_schema.tables** por **information_schema.columns**, ya que queremos saber las columnas de la tabla **users**, y agregamos la cláusula **LIKE**, para intentar descubrir nombres de columnas.

<br>

Así que tras intentar descubrir cada columna encontramos 3:

- **id**
- **username**
- **password**

<br>

![pass1](/assets/images/SQLi/pass1.png)

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 FROM information_schema.columns WHERE table_schema = 'sqli_four' AND table_name = 'users' AND column_name LIKE 'username%' ; --`

<br>

Vemos que ya encontramos las columnas que nos interesan, en este caso nos llaman la atención **username** y **password**, por lo que procederemos a enumerar su contenido, empezando por el **username**:

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 FROM sqli_four.users WHERE username LIKE 'a%' ; --`
<br>

Al intentar varias veces hasta descubrir lo que hay en la columna **username** encontramos el usuario **admin**:

![admin5s](/assets/images/SQLi/admin5s.png)

<br>

Ya no buscamos más usuarios porque encontramos el que tiene nombre interesante, aunque nunca esta de más enumerar todo como sea posible, ahora que ya tenemos el usuario **admin** que encontramos en la columna **username** solo queda filtrar la columna **password** o sea contraseña, de dicho usuario.

<br>

Por lo que haremos una nueva consulta:

`https://website.thm/analytics?referrer=admin5' UNION SELECT SLEEP(5),2 FROM sqli_four.users WHERE username = 'admin' AND password LIKE 'a%' ; --`

<br>

En este caso estamos agregando la columna **password** y para descubrir su valor como sabemos jugamos con LIKE, vemos que dejamos la columna **username** con el valor **admin**,ya que queremos el valor de la columna **password** de dicho usuario.

<br>

Ahora como sabemos trataremos de enumerar el valor de **password** del usuario admin, por lo que al intentar con la consulta anterior descubrimos que dicho valor de esa columna es **4961**, por lo que ya hemos descubierto el usuario y contraseña para terminar este nivel!

![endd](/assets/images/SQLi/endd.png)

<br>

Como ya terminamos con esto, siguen más niveles que veremos en una plataforma distinta, en este link esta la segunda parte sobre SQL inyection: [SQLi - Portswigger](https://dantedansh.github.io/SQL-Injection-SQLi-PortSwigger/)

<br>
