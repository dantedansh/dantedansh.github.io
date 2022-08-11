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

![select](/assets/images/SQLi/select_especifico.png)

<br>

Ahora el comando que sigue es **LIMIT**, esto nos va a permitir saltar y mostrar solo una fila o a partir de una fila hacia abajo, por ejemplo:

`MariaDB [Escuela]> select * from Alumnos LIMIT 1;`

Aquí le estamos indicando que nos seleccione todo de la tabla **Alumnos** para después con **LIMIT** mostrarnos limitando el número de filas que saltara y mostrara a partir de una fila en base a los valores que le pasaremos, en este caso solo pusimos 1, que esto significa que solo nos mostrara la primera fila y el resto no, se verá así:

![select](/assets/images/SQLi/limit1.png)

> Cuando pasamos solo un valor y no 2 entonces se tomara ese valor como las primeras filas que quieres ver empezando desde la primera.

<br>

Ahora si queremos omitir la primera fila, pero mostrar las siguientes 2 entonces hacemos:

`MariaDB [Escuela]> select * from Alumnos LIMIT 1,2;`

Y veremos que nos saltó la primera fila, y a partir de la que sigue de la que saltamos nos mostró las 2 que seguían hacia abajo viéndose así:

![select](/assets/images/SQLi/limit1-2.png)

> LIMIT X,Y en el valor X va las filas que saltara, y el valor Y las filas que mostrara a partir de la que sigue de las que saltamos.

<br>

# cláusula "where" para filtrar datos

Lo primero que veremos es como hacer para que nos filtre datos con precisión de lo que queremos, por ejemplo en esta cadena:

`MariaDB [Escuela]> select * from Alumnos where usuario="dansh";`

Vemos que primero selecciona todo de la tabla **Alumnos**, para después decirle que de la columna **usuario** nos mostrara las filas que tengan el valor de "dansh" en la columna **usuario** y luego nos las muestre, por lo que se verá así:

![select](/assets/images/SQLi/where_1.png)

Como solo hay una fila que en la columna **usuario** tenga el valor de "dansh" solo veremos 1 pero en caso de haber más nos los mostraría.

<br>

Ahora veremos la condición **!=** con **where**:

Ahora veremos lo mismo, pero inverso, ahora queremos ver las filas que NO sean igual a un valor dentro de una columna, por ejemplo, si no queremos que nos muestre las filas que en su columna **usuario** tengan de valor "dansh", haremos esto:

`MariaDB [Escuela]> select * from Alumnos where usuario != "dansh";`

Seleccionamos todo lo de la tabla **Alumnos**, después decimos que las filas de la columna usuario que NO tengan de valor "dansh" se mostraran, así que veremos todas las filas que no tengan de valor "dansh" en la columna **usuario**:

![select](/assets/images/SQLi/where_not.png)

<br>

Ahora veremos la condición **or** con **where**:

