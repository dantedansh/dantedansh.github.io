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



# Bases de datos relacionales y no relacionales

**Relacional:**

Una **base de datos relacional** es la que guarda datos en tablas y es común que se compartan información entre ellas, y estas tablas usan columnas para saber de qué son los datos que estás mostrando en esa tabla, y las filas son los datos para esas columnas que especificamos, por ejemplo la columna "Nombre" puede tener una fila con un dato conforme al valor de lo que definimos anteriormente, por ejemplo un nombre seria "Dansh".

Estas tablas comúnmente contienen una **ID** que esta **ID** se puede usar para hacer referencia a ellas en otras tablas y como comparten información se le llama **"Base de datos Relacional"**.

**No Relacional:**

Y la **base de datos no relacional** que se les llama NoSQL, a las relacionales se les dice MySQL, entonces como esta es **no relacional** no usa ni tablas, ni columnas ni filas, esto lo almacena como si fuese un documento con una estructura básica como **XML** o **JSON**, y cada registro se le asigna una clave única para poder ubicar esos datos.