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



# ¿Que es SQL?

Antes de ver **SQLi** debemos saber como funciona **SQL**, es un lenguaje de consulta estructurada, esto quiere decir que con las consultas también llamadas declaraciones, nos sirve para manipular una base de datos y organizar información en forma de bases de datos relacionales.

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

# Tipos de Inyecciones SQL

**In-Band SQL Inyection** trata sobre una vulnerabilidad no tan complicada, ya que puedes explotar la vulnerabilidad desde la misma página web y ver en pantalla los resultados, existen 2 maneras la **Basada en errores** y **Basada en unión**.

<br>

# Inyección Basada en errores

La inyección SQL **Basada en errores** nos es más útil y rápida para obtener información de como está estructurada la base de datos que corre en la página web, esto nos puede servir para ir enumerando la base de datos conforme a los resultados y podríamos extraer información importante de la **estructura** de la base de datos.

# Inyección Basada en unión

Esta inyección **Basada en unión**, nos es útil para poder extraer datos usando el operador de SQL **UNION** junto con la declaración **SELECT** para devolver grandes cantidades de datos dentro de la base de datos.

<br>

# Prueba de inyección In-Band

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

De la misma manera podríamos saber otras cosas como por ejemplo ver la base de datos actual:

![database](/assets/images/SQLi/database.png)

Vemos que ahora la url es:

`http://testphp.vulnweb.com/listproducts.php?cat=0 union select 1,2,3,4,5,6,database(),8,9,10,11 --`

Que esa es la función que nos devuelve la base de datos actual en uso que en este caso se llama **acuart** como vemos en la respuesta de la consulta.

<br>

Ahora seguiremos probando cosas, pero esta vez usando una máquina de una sala de try hack me que es la siguiente:

[TryHackMe](https://tryhackme.com/room/sqlinjectionlm)

Prueba-new-arch
