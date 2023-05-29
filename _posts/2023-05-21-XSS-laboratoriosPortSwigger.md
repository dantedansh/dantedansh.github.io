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

![lab2](/assets/images/XSS/lab2/lab2.png)

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

# laboratorio 3: DOM XSS in document.write sink using source location.search

![lab3](/assets/images/XSS/lab3/lab3.png)

En este laboratorio vemos que dice que contiene una vulnearbilidad XSS en la función de busqueda.

Nos dice que por detras existe la función **document.write** la cual encontramos aquí viendo la fuente de la web:

![documentwrite](/assets/images/XSS/lab3/documentwrite.png)

Y vemos que encontramos la siguiente función buscando por "document.write":

```js

function trackSearch(query) {
	document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
	trackSearch(query);
}
```

Y viendo el código vemos que se usa **document.write** para mostrar resultados en la página.

Y en la función principal de este ejemplo llamada **trackSearch**, recibe un parametro llamado **query**, y vemos que en la linea de:

`document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');`

Solamente lo esta concatenando en la parte de **document.write**, sin filtros, ni nada para evitar un ataque XSS, simplemente se está pasando concatenado en el recurso cargado que en este caso es una imagen .gif y seguido de eso se esta concatenando de marena erronea, ya que el parametro pasado que es **query** contiene los datos que le hemos pasado como busqueda en la función de busqueda de la web.

Y esto es un error, ya que como no se esta sanitizando la entrada de datos, y simplemente se estan concatenando directamente en la consulta, entonces podriamos inyectar código javascript, y como estamos viendo como funciona esto, será facil evadir el valor de las comillas y escapar para que nos interprete nuestro código javascript.

<br>

Para ello vemos que al final donde se esta concatenando el valor query, esta encerrado entre comillas simples, y anterior a eso hay unas comillas dobles, y anterior a eso estamos dentro de un `<img src` el cual debemos cerrar para posteriormente agregar nuestro código.

Así que para salir de las comillas simples y dobles y también para cerrar el `<img src` haremos lo siguiente, pondremos esto en la función de busqueda de la web:

`'"><script>alert(1)</script>`

> Lo que estamos haciendo es cerrar el contenido de la primera comilla simple por detras, así que ahora cerramos las siguientes comillas dobles poniendo **"** y por ultimo con **>** cerramos el <img scr>, seguido de nuestro script invocando a la función de alerta ya que el objetivo de este nivel es hacer esto.

Una vez hagamos la busqueda de esto, por detras habremos escapado de las comillas y del img src, lo que ocacionara que nuestro código sea interpretado por el servidor mostrandonos lo deseado:

![alert](/assets/images/XSS/lab3/alert.png)

Podemos apreciar el mensaje de alerta, y podemos ver que hemos completado este laboratorio:

![end](/assets/images/XSS/lab3/end.png)

> Debajo de la busqueda podemos ver **">** que son los valores que quedaron fuera ya que cerramos nosotros los anteriores quedando esos recorriendose hasta el final, y aparecen ahí ya que ahí es donde debía mostrarse la imagen.gif de la cual abusamos para que funcione nuestro XSS-DOM-based.

<br>

# Laboratorio 4: DOM XSS in innerHTML sink using source location.search

En este cuarto laboratorio de XSS basado en DOM, vemos que nos dice lo siguiente:

![lab4](/assets/images/XSS/lab4/lab4.png)

Nos dice que tiene una vulnerablidad XSS Dom-Based, en la función de busqueda, y que usemos una asignación de HTML interna que cambia el contenido HTML de un elemento div usando los datos que obtenemos de **location.search**, y que para terminar este laboratorio debemos mostrar una alerta como anteriormente lo hemos estado haciendo.

![location](/assets/images/XSS/lab4/location.png)

Filtrando en el código de la web por **location.search**, encontramos un código parecido al del laboratorio anterior, este código que encontramos es este:

```js
function doSearchQuery(query) {
	document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
	doSearchQuery(query);
}
```

Primero vemos que se esta usando **document.getElementById**, lo que hace esto es que se utiliza para obtener una referencia a un elemento dentro del DOM mediante su identificador unico, donde en este caso el identificador unico que es lo que esta dentro, es **searchMessage**, y buscando en el código de la web este id, encontramos lo siguiente:

![search](/assets/images/XSS/lab4/search.png)

Vemos la linea:

`<span id="searchMessage">Prueba</span>`

Y descubrimos que este identificador único hace referencia a nuestro texto de entrada en la función de busqueda, ya que buscamos "Prueba" y vemos que se guarda en ese id.

Entonces sabemos que el valor de **SearchMessage** del código hace referencia a ese lugar.

Y como abajo vemos que se llama a esa función y gracias a eso podemos ver lo que ingresamos como datos en la respuesta de la web.

Entonces haremos lo siguiente:

![onerror](/assets/images/XSS/lab4/onerror.png)

`<img src=noexist onerror=alert(1)>`

Lo que estamos haciendo con esta linea es que la web tome nuestros datos de entrada, y como esta usando **innerHTML**, nos leera nuestro código inyectado y lo interpreatara, gracias a que no se esta sanitizando la entrada de los datos en el código de la web.

Y lo que hace esa linea es cargar una imagen que no existe, forzando que se redirija al caso de error de la derecha lo cual lo que hará es ejecutar una alerta que le hemos dicho que haga.

Y como estamos forzando que esto sucedea, al buscar esto veremos que nos responde lo siguiente:

![alert](/assets/images/XSS/lab4/alert.png)

Y habremos terminado este laboratorio:

![end](/assets/images/XSS/lab4/end.png)

<br>

