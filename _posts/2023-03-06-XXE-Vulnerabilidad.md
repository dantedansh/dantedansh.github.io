---
layout: single
title: Vulnerabilidad XXE - ¿Qué es y como se explota?
excerpt: "En este post explicaremos que es una vulnerabilidad XXE, Y como se puede explotar."
date: 2023-03-06
classes: wide
header:
  teaser: /assets/images/XXE/
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - XXE
  - XML
---

<br>

# ¿Qué es XML?

![XMLdraw](/assets/images/XXE/XMLdraw.png)

El Lenguaje de marcado extensible nos permite definir y guardar datos de forma compartible, y los datos que se transmiten son fácil de leer y facilita la transmisión de datos.

<br>

El XML tramita los datos en una estructura de arbol, similar a HTML, y los principales valores que se pasan son Etiquetas y Datos:

![Datags](/assets/images/XXE/datags.png)

<br>

Y aquí podemos ver un ejemplo de como viaja la petición y se interpreta:

![Peticion](/assets/images/XXE/peticion.png)

<br>

Ahora necesitamos saber que son las entidades, que son una forma de representar elementos de datos sin necesidad de hacer referencia a esos datos, esto se hace dentro de un documento XML.

principalmente usaremos 3 tipos de entidades:

![entidades](/assets/images/XXE/entidades.png)

Vemos la definicion de cada una de ellas, y aunque no te quede muy claro, ahora veremos ejemplos.

<br>

# Ejemplo de entidad Genérica

Primero veremos la siguiente estructura de arbol XML:

```xml

<?xml version="1.0" encoding="UTF-8">
<nombre>Dansh</nombre>
<id>1</id>

```

Podemos ver que es una estructura XML basica pero nos servira para el ejemplo, en este caso esta estructura contiene las etiquetas **nombre** y **id**, con sus valores dentro definidos.

Esta entidad nos debería dar el resultado en pantalla que diga: nombre-Dansh id-1.

Ahora lo que vamos a hacer será agregar nuestra propia entidad, y la haremos agregando esta linea a el codigo quedando así:

```xml

<?xml version="1.0" encoding="UTF-8">
<!DOCTYPE foo [ <!ENTITY name "Dan"> ]>
<nombre>&name;</nombre>
<id>1</id>

```

Como podemos ver, hemos agregado en la segunda linea eso que se muestra, lo que estamos haciendo es crear una entidad llamada **name** con el valor de "Dan".

Y podemos ver abajo que estamos haciendo referencia a la entidad llamada **name**, la cual tomara el valor y lo pondra dentro de las etiquetas de donde ha sido llamada.

Y esta entidad anterior nos debería dar un resultado así: nombre-Dan id-1.

> Vemos que el valor de la etiqueta nombre ha cambiado ya que hemos creado una entidad y la hemos usado en las etiquetas nombre para hacer referencia al valor de dicha entidad.