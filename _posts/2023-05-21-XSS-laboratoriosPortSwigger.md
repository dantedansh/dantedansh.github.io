---
layout: single
title: XSS - ¿Qué es y como se explota?
excerpt: "Como se acontece una vulnerabilidad XSS, tipos y laboratorios de PortSwigger."
date: 2023-05-21
classes: wide
header:
  teaser: /assets/images/XSS/banner.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - javascript
  - XSS
  - PortSwigger
---

<br>

# ¿Qué es XSS?

La vulnerabilidad XSS (cross site scripting), es una vulnerabilidad que nos permite inyectar codigo malicioso, comunmente los ataques se hacen usando javascript, esta vulnerabilidad se acontece cuando el desarrollador de la web no valida ni filtra adecuadamente los datos que son ingresados por el usuario antes de ser mostrada en la página web.

<br>

El funcionamiento de esta vulnerabilidad radica en que un atacante puede ingresar código malicioso en algun campo de entrada de datos, como lo puede ser un buscador en la web, algún comentario, o cualquier campo que nos permita ingresar datos y dichos datos se vean reflejados, ya sean temporalmente o no.

<br>

Y digo temporalmente o no ya que existen diferentes tipos de XSS, los más comunes son:

XSS Reflejado(reflected): Esto sucede cuando el código inyectado es interpretado por el servidor web y nos manda la respuesta de dicho codigo ya que nuestro navegador recibe esa respuesta y nos la muestra.

XSS Almacenado(Stored): Es cuando el código inyectado se almacena dentro de los servidores de la web, por ejemplo, si hacemos un comentario donde gracias a la vulnerabilidad cualquier codigo javascript comentado en la web se interpretará en lugar de se un simple comentario, y como los comentarios se guardan en una base de datos, entonces esta respuesta que obtuvimos no solo será visible para nosotros, si no que cualquier persona que entre a la web y vea el comentario podrá leer la respuesta del código que inyectamos en un inicio.

XSS Dom-Based: Este ataque es cuando el código es inyectado en el DOM(Modelo de objetos del documento) de la página web, y el DOM es una estructura que se utiliza para poder leer el código de una mejor forma para los desarrolladores, el DOM tiene una estructura de arbol, donde se separan los elementos HTML de la web como objetos en este DOM, una imágen representativa de ejemplo es la siguiente:

![DOM](/assets/images/XSS/DOM.png)

Podemos apreciar como se divide en un formato de multiples objetos y se separa la web para una mejor readacción y corrección en caso de ser necesario.

Ahora que ya entendimos un poco sobre lo que es el DOM, seguiremos explicando el XSS basado en DOM, Así que una vez inyectado el código en el DOM, entonces podremos obtener una respuesta del servidor vulnerable y la veremos reflejada en el campo que nos devuelve algún valor por defecto pero obviamente nos devolvera lo que hemos inyectado ya que estamos reemplazando ese valor por un código malicioso directamente en el DOM, y esto no se almacena en los servidores, ya que estamos modificando la estructura actual de la web, de todos modos lo veremos más adelante con laboratorios para entender esto de mejor forma.

<br>

# Laboratorio 1: XSS reflejado en contexto HTML sin nada codificado

Vemos que en este primer laboratorio nos piden hacer lo siguiente:

![lab1](/assets/images/XSS/lab1/lab1.png)

Dice que este laboratorio contiene un XSS simple reflejado(reflected), en la función de busqueda.

Y que para terminar este laboratorio debemos llamar a la función de alert que ejecuta javascript.

<br>

Lo primero que haremos al entrar al laboratorio es ver la función de busqueda:

![search](/assets/images/XSS/lab1/search.png)

Podemos ver que esta la función de busqueda, buscaremos cualquier cosa, por ejemplo "Hola":

![hola](/assets/images/XSS/lab1/hola.png)

Vemos que no ha encontrado resultados, pero es no nos interesa, lo que nos interesa es que sabemos que la vulnerabilidad se encuentra en este apartado de la web, y que los datos que estamos ingresando como usuario se ven reflejados en la respuesta, buscamos "Hola" y en la respuesta nos dice: 0 search results for "Hola", por lo que estamos viendo lo que ingresamos en la respuesta, y si es vulnerable a este XSS simple refjeado, entonces al meter código en la busqueda en lugar de alguna busqueda nos debería interpretar ese codigo.

Como el reto de este laboratorio es desplegar un mensaje de alerta es lo que agregaremos como código inyectado:

`<script>alert(1)</script>`

> De esta forma en javascript llamamos a la función de alerta para que nos muestre un mensaje en pantalla de la web.

![script](/assets/images/XSS/lab1/script.png)

Así que al buscar esto, el servidor interpretara nuestro código javascript inyectado ya que por detras no se esta securizando la entrada de datos por lo que pueden pasar cosas como estas y que el servidor logre interpretar lo que queremos.

Así que al darle en "search", se enviará la petición y veremos que nos ha respondido la alerta:

![alert](/assets/images/XSS/lab1/alert.png)

Vemos el mensaje de alerta lo cual indica que esto es vulnerable y habremos terminado con este laboratorio ya que el objetivo era esto, algo simple.

![end](/assets/images/XSS/lab1/end.png)

<br>

# Laboratorio 2: XSS almacenado en contexto HTML sin nada codificado

![lab2](/assets/images/XSS/lab1/lab2.png)

Este laboratorio nos dice que existe una vulnerabilidad XSS almacenada(stored) en la sección de comentarios, así que al abrir algún producto del laboratorio vemos la siguiente sección de comentarios:

![comentarios](/assets/images/XSS/lab2/comentarios.png)

Como podemos ver, tenemos la posibilidad de dejar comentarios en esta página web, y como estos comentarios se almacenan en los servidores para que todos los usuarios puedan verlos, entonces en caso de que podamos acontecer un XSS aquí en un comentario entonces no solo lo veriamos nosotros, si no que también todos los que entren a esta sección de la web.

Así que intentaremos dejar un comentario llamando a la función alert de javascript:

`<script>alert(1)</script>`

![script](/assets/images/XSS/lab2/script.png)

Y ahora posteamos el comentario:

![posted](/assets/images/XSS/lab2/posted.png)

Y ahora cualquier persona que entre a este apartado de la web le saldrá la siguiente alerta:

![alert](/assets/images/XSS/lab2/alert.png)

Ya que el comentario que pusimos contiene el código javascript lo cual hace que cada que entren esta función se ejecute mostrandonos el mensaje ya que se guardo dentro de la base de datos y el servidor mismo lo interpreta y nos lo muestra.

Y con esto habremos completado este laboratorio:

![end](/assets/images/XSS/lab2/end.png)

<br>

# laboratorio 3: 