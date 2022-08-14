---
layout: single
title: Inyección SQL - SQLi
excerpt: "Explicación de como se detecta y explota una vulneravilidad de tipo SQLi."
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
---



# ¿Que es SQLi?

**SQLi** es un ataque hacia un servidor de bases de datos web que consiste en ejecutar peticiones maliciosas usando la entrada de usuario, esto sucede cuando no está bien sanitizada la base de datos y podríamos aprovecharnos de esto para desplegar las bases de datos que están disponibles en el servidor web.

<br>



# ¿Cómo está conformada una base de datos?

![Tabla](/assets/images/SQLi/DBMS.png)

En el primer bloque vemos que está el servidor de la base de datos, que este es el que contiene las bases de datos dentro de ella.

Después vemos que en la base de datos "Escuela" tiene 2 tablas, una de Alumnos y otra de Aulas, y cada tabla tiene sus respectivos valores que se asignaron en el DBMS.

Al lado derecho vemos otra base de datos que es prácticamente lo mismo pero con diferente información, pero vemos que es posible tener más de 1 base de datos dentro del servidor de bases de datos.

<br>

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

# Bases de datos relacionales y no relacionales

**Relacional:**

Una **base de datos relacional** es la que guarda datos en tablas y es común que se compartan información entre ellas, y estas tablas usan columnas para saber de qué son los datos que estás mostrando en esa tabla, y las filas son los datos para esas columnas que especificamos, por ejemplo la columna "Nombre" puede tener una fila con un dato conforme al valor de lo que definimos anteriormente, por ejemplo un nombre seria "Dansh".

Estas tablas comúnmente contienen una **ID** que esta **ID** se puede usar para hacer referencia a ellas en otras tablas y como comparten información se le llama **"Base de datos Relacional"**.

**No Relacional:**

Y la **base de datos no relacional** que se les llama NoSQL, a las relacionales se les dice MySQL, entonces como esta es **no relacional** no usa ni tablas, ni columnas ni filas, esto lo almacena como si fuese un documento con una estructura básica como **XML** o **JSON**, y cada registro se le asigna una clave única para poder ubicar esos datos.


<br>

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

# La instrucción INSERT

