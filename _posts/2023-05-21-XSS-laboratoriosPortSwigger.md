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

```js
<script>alert(1)</script>
```

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

```js
<script>alert(1)</script>
```

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

```js
document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
```

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

```js
<span id="searchMessage">Prueba</span>
```

Y descubrimos que este identificador único hace referencia a nuestro texto de entrada en la función de busqueda, ya que buscamos "Prueba" y vemos que se guarda en ese id.

Entonces sabemos que el valor de **SearchMessage** del código hace referencia a ese lugar.

Y como abajo vemos que se llama a esa función y gracias a eso podemos ver lo que ingresamos como datos en la respuesta de la web.

Entonces haremos lo siguiente:

![onerror](/assets/images/XSS/lab4/onerror.png)

```js
<img src=noexist onerror=alert(1)>
```

Lo que estamos haciendo con esta linea es que la web tome nuestros datos de entrada, y como esta usando **innerHTML**, nos leera nuestro código inyectado y lo interpreatara, gracias a que no se esta sanitizando la entrada de los datos en el código de la web.

Y lo que hace esa linea es cargar una imagen que no existe, forzando que se redirija al caso de error de la derecha lo cual lo que hará es ejecutar una alerta que le hemos dicho que haga.

Y como estamos forzando que esto sucedea, al buscar esto veremos que nos responde lo siguiente:

![alert](/assets/images/XSS/lab4/alert.png)

Y habremos terminado este laboratorio:

![end](/assets/images/XSS/lab4/end.png)

<br>

# Laboratorio 5: DOM XSS in jQuery anchor href attribute sink using location.search source

En este laboratorio nos dan las siguientes instrucciones:

![lab5](/assets/images/XSS/lab5/lab5.png)

Nos dice que este laboratorio contiene un XSS Basado en DOM, el cual se encuentra en la página de feedback, también nos dice que debemos utilizar la función selectora $ de la biblioteca de Jquery, esto para encontrar un elemento ancla(anchor) y cambiar su atributo href, utilizando datos de location.search.

La función selectora $, es una función que esta integrada en la biblioteca de Jquery, y esto lo que nos permite hacer es seleccionar elementos HTML y nos sirve para manipular el DOM.

Y lo que nos dice de encontrar un elemento ancla y cambiar su atributo href, se refiere a que debemos encontrar ese atributo href al que menciona el $ de jquery que debemos encontrar en el código de la web, y revisar de que forma podriamos manipular los datos de entrada.

<br>

Primero al ir a la sección de **Submit feedback** como nos dice el laboratorio vemos lo siguiente:

![feedback](/assets/images/XSS/lab5/feedback.png)

Así que analizando un poco el código de la web encontramos lo siguiente:

![back](/assets/images/XSS/lab5/back.png)

```js
<a id="backLink" href="/post">Back</a>
```

Lo que hace esta linea de HTML, crea un enlace con el texto **Back**, que al darle click te redirijira a la ruta **/post** de la web, y este enlace tiene un identificador unico ID, el cual tiene como valor **backLink** para acceder a el.

Y más abajo de esto encontramos lo siguiente:

![function](/assets/images/XSS/lab5/function.png)

```js
$(function() {
  $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

Y lo que esta sucediendo aqui es que con jquery, se esta seleccionando un elemento el cual tiene un identificdor unico ID con el valor de **backLink**, el cual ya habiamos visto antes, y vemos que se esta tomando el valor del parametro **returnPath**, y después esto se envia al atributo **href** del enlace, el cual es **backLink** y sabemos que este enlace te lleva a:

```js
<a id="backLink" href="/post">Back</a>
```

Así que si como atacantes podemos tener acceso a la entrada del parametro **returnPath** podriamos ingresar código malicioso y si no esta sanitizado entonces se interpretaria nuestro código malicioso.

<br>

Hagamos una prueba, como podemos ver, en la página en la que estamos de **Submit feedback**, si miramos bien en la URL, tenemos acceso a dicho parametro, ya que la petición se tramita por el metodo **GET**, por lo que tenemos acceso a dicho parametro como podemos observar en la URL:

![url](/assets/images/XSS/lab5/url.png)

`feedback?returnPath=/post`

Podemos apreciar que en este caso por defecto esta /post, lo cual nos llevaría al post anterior, pero como nosotros podemos manipular esta entrada de datos, intentaremos inyectar nuestro código malicioso, el cual es mostrar una alert de una cookie como nos pide el objetivo del laboratorio, así que la ingresaremos:

`feedback?returnPath=javascript:alert(document.cookie)`

![code](/assets/images/XSS/lab5/codemalicious.png)

Lo que estamos haciendo aqui es ingresar codigo que se interprete usando javascript, y lo que hace es mostrarnos una alerta con el valor de la cookie.

Y ahora si revisamos el código de la web:

![value](/assets/images/XSS/lab5/value.png)

Podemos apreciar que el valor que estaba por defecto el cual era **/post** se ha reemplazado por nuestro código malicioso y también se ha interpretado, así que ahora cada que demos click en el boton de **"Back"** nos mostrara la alerta con la cookie, y esto es ya que hemos modificado el valor al cual hacia referencia la entrada por defecto, cambiandola por nuestro código malicioso y todo gracias a que tuvimos acceso de entrada de datos a dicho parametro.

Y habremos terminado el laboratorio:

![end](/assets/images/XSS/lab5/end.png)

<br>

# Laboratorio 6: DOM XSS in jQuery selector sink using a hashchange event

En este laboratorio nos dice lo siguiente:

![lab6](/assets/images/XSS/lab6/lab6.png)

Nos dice que este laboratorio tiene una vulnerabilidad XSS basada en DOM, la cual se encuentra en la página de inicio.

También nos dice que usa la función selectora $() de Jquery para desplazarnos automaticamente a una publicación asignada, y el valor de la publicación asignada se le asigna a través de la propiedad **location.hash**.

Para entender mejor veamos lo siguiente.

<br>

Primero analizaremos el código de la web, y buscando por **hashchange** encontramos lo siguiente:

![home](/assets/images/XSS/lab6/home.png)

```js
$(window).on('hashchange', function(){
  var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
  if (post) post.get(0).scrollIntoView();
});
```

Lo que hace este código es la función que hace que nos podamos desplazar automaticamente a una publicación usando el #, por ejemplo, si en alguna pagina web con multiples secciones por ejemplo, indice,manual,etc. si queremos ir a manual automaticamente debemos agregar el simbolo de #, al final de la url, quedando algo así:

`https://prueba.com/#Manual`

Esto nos situara automaticamente en la página que tenga el elemento "Manual", y nos llevara a esa sección ya que previamente se ha configurado una función como la del codigo javascript y para saber como funciona este código de js.

A continuación, detallo el funcionamiento del código:

Lo que hace ese código a detalle, es que primero selecciona los elementos que se encuentra entre las etiquetas **<h2>** de HTML utilizando el selector de CSS, **section.blog-list h2**, que con esto obtenemos todos los titulos de los post en la web, así que por el momento selecciona todos los titulos para despues hacer una comparacion y ver cual coincide con nuestra busqueda en el #.

Y podemos apreciar que en efecto los titulos de los post se guardan entre estas etiquetas:

![h2](/assets/images/XSS/lab6/h2.png)

Vemos en el código de la web que todos los titulos estan guardados entre las etiquetas **<h2>**, por lo que por eso guardamos todos los elementos que esten dentro de estas etiquetas en la página web de inicio.


Una vez tenga estos titulos guardados, lo que hace es usar la función **decodeURIComponent()**, la cual dentro de ella tiene los siguientes parametos:

```js
decodeURIComponent(window.location.hash.slice(1))
```

Primeramente, lo que hace **window.location.hash**, es que filtra el valor que pusimos como parametro de busqueda pero este se devuelve con todo y el #.

Por ejemplo, si la URL completa con nuestra busqueda de **"Carros"** es:

`https://prueba.com/#Carros`

Entonces la función anterior, debería devolver:

`#Carros`

Pero como la función aún no termina y vemos otro valor el cual es: **slice(1)**, entonces lo que hace esto es eliminar el primer caractér, el cual es el #, quedandonos solo el valor:

`Carros`

Y ahora con este valor que pasamos decodificado, se usa la función **:contains()** que lo que hace es seleccionar nuestro elemento anteriormente guardado, y después este elemento se compara con los que tomamos de la lista **section.blog-list** en un principio.

Y por último, en caso de que nuestro elemento ingresado coincida con alguno de la lista, entonces nos lleva ahí usando la función **scrollIntoView()**.

Así que en resumen, lo que hace este código de javascript, es que como dije antes, nos permite ir a alguna sección de la página web, utlilizando el valor de la URL y haciendo modificaciones en el DOM podemos lograr esto.

<br>

Pero por otro lado, este código no es del todo seguro:pues en el código anterior, recide un pequeño detalle, que podría convertirse en algo peligroso.

Y me refiero a que al momento de recibir la entrada del usuario, no se esta aplicando ningun filtro de seguridad, así que veamos a lo que me refiero:

En el código vemos la siguiente linea:

```js
var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
```

Como recordamos, la función **decodeURIComponent()** en este caso la usamos para filtrar el valor de busqueda pasado por medo de la URL, y lo obtenemos sin el # como ya lo sabemos.

Pero como no se esta realizando ningun tipo de filtro de seguridad, para evitar que el código malicioso se interprete, entonces un atacante podría meter código directamente como si fuese una busqueda de alguna sección en la página web, pero en verdad es código malicioso que como no hay filtros, entonces se interpretará ejecutando la acción deseada del atacante.

Por ejemplo:

`https://prueba.com/#<script>alert('Vulnerable')</script>`

Lo que sucederá es que como no hay filtros como había dicho anteriormente, entonces esto se ejecutará en nuestro navegador usando como base la página web.

> Por esto es importante saber sanitizar código, sobre todo en las entradas de datos.

Así que con esto, estamos más cerca de lograr el objetivo de este laboratorio, el cual es crear una URL para que al enviarsela a la victima, se le ejecute la función **print()** de javascript.

Así que sabiendo esto, haremos la siguiente URL maliciosa:

`<iframe src="https://prueba.com/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`

La función que tiene la etiqueta **iframe** es que primero carga la web que esta en su src, que en este caso es la URL del laboratorio, pero como sabemos que lo anterior es vulnerable a XSS gracias a la función de javascript no sanitizada, entonces agregamos el # para inyectar nuestro código, y este código es el siguiente.

Cuando ya se termine de cargar la URL del iframe, entonces lo que sucederá es que el evento **onload** se ejecutará, y esto lo que hace es que agrega dinamicamente la linea:

```js
<img src=x onerror=print()>
```

Al final de la URL en el src del iframe, sabemos que esta pequeña linea lo que hace es cargar una imagen inexistente para después forzar un error y ejecutar en este caso la función print().

Así que una vez el iframe se cargo, pasará de ser:

`https://prueba.com/#`

A ser:

`https://prueba.com/#<img src=x onerror=print()>`

De esta forma como hay un cambio, entonces como hubo un cambio, el iframe lo detecta, cargandonos la nueva URL y aqui es donde se acontece la vulnerabilidad ya que al hacer esto, ya nos estaría interpretando nuestro código malicioso.

Se hace en forma de una linea de código ya que así nos lo pide el laboratorio, pero en un caso real sería algo así:

`https://test.com/#onload="this.src+='<img src=x onerror=print()>'"`

Ya que al enviar a alguien esta URL, le interpretará el código inyectado, aconteciendo la vulnerabilidad de su lado, de esta forma se puede llegar a robar cookies de sesion, o más cosas del estilo.

Así que al enviar este código final al atacante:

![exploit](/assets/images/XSS/lab6/exploit.png)

Podemos ver que al dar en enviar exploit a la victima, hemos resuelto el laboratorio:

![fin](/assets/images/XSS/lab6/fin.png)

<br>

# Laboratorio 7: Reflected XSS into attribute with angle brackets HTML-encoded

En este siguiente laboratorio, vemos que nos dice lo siguiente:

![lab7](/assets/images/XSS/lab7/lab7.png)

Dice que este laboratorio tiene una vulnerabilidad XSS Reflected(Reflejada), en la función de busqueda de la web, y nos dice que para completar este laboratorio debemos inyectar un atributo al código y llamar a la función alert().

Al entrar a la web, y buscar algo nos carga lo siguiente:

![prueba](/assets/images/XSS/lab7/prueba.png)

Vemos que es un buscador normal, y no vemos nada extraño, por lo que abriremos la herramienta para inspeccionar el código de la web, y para encontrar donde esta la vulnerabilidad, podemos intuir que el XSS recide en la entrada de datos, por lo que filtraremos por nuestra palabra que buscamos para ver que se esta haciendo con ese valor dado, en este caso filtramos por **"Prueba"** ya que fue lo que buscamos.

Y encontramos lo siguiente:

![html](/assets/images/XSS/lab7/html.png)

```js
<input type="text" placeholder="Search the blog..." name="search" value="Prueba">
```

Podemos apreciar que en esta linea, cuando se recibe el valor de nuestra busqueda que en este caso se almacena en **value**, y vemos que no esta muy bien creada esta parte, ya que de no estar sanitizada la entrada de datos, podriamos llegar a inyectar código javascript y que el servidor lo interprete.

Para ello, intentaremos escapar de las comillas dobles, e intentar inyectar nuestro código, que en este caso, nos piden mostrar un alert através de un atributo.

Si vemos bien en la linea de código, vemos que la sintaxis es un atributo, seguido de su valor: type es "text", placeholder es "Search the blog...", name es "search", y por último value es al que tenemos entrada.

siguiendo esta sintaxis, entonces debemos agregar un atributo que nos permita ver reflejado el código javascript que estará dentro de el.

<br>

Para ello podemos usar el atributo **onmouseover**, que en pocas palabras lo que hace este atributo es que al momento que el cursor pase encima de donde se esta usando, se muestre lo que le indiquemos automaticamente al pasar el cursor por encima de ese elemento, que en este caso es en el elemento HTML de entrada que recibe el buscador web.

Ahora con lo anterior en cuenta, entonces ya sabemos lo que hará al meter el siguiente valor en la función de busqueda:

![mouse](/assets/images/XSS/lab7/mouse.png)

```js
Prueba"onmouseover="alert(1)
```

Lo que estamos haciendo en esto, es que primero, estamos poniendo el valor que recibira el atributo **value**, que en este caso es "Prueba", pero seguido de eso usamos unas comillas dobles, y esto es para poder cerrar el atributo **value**, y procedemos a escribir el nuevo atributo que como sabemos es **onmouseover** del cual ya sabemos su función, dandole como valor la función alert() de javascript, pero notamos que después de poner el = hay otras comillas dobles.

Y esto es para que tome la sintaxis de los atributos anteriores, y al final no pusimos otras comillas dobles, ya que como sabemos, al momento de poner las primeras que usamos para cerrar el atributo **value**, estas comillas dobles por detras se arrastraron hacia el final, y aqui no ponemos nada ya que por detras ya hay unas comillas dobles que nos cerrararan el valor del atributo inyectado.

Así que en teoria por detras debería verse así:

```js
<input type="text" placeholder="Search the blog..." name="search" value="Prueba" onmouseover="alert(1)">
```

> Aunque no hayamos dado un espacio para separar un atributo del otro no importa ya que automaticamente se agregan evitando errores.

Así que al tramitar esta busqueda podemos ver lo siguiente:

![alert](/assets/images/XSS/lab7/alert.png)

Podemos apreciar que cada que pasemos el cursor por encima de la función de busqueda donde ahí recide el input del atributo **value**, entonces en esa parte podremos ver que se ejecuta el atributo **onmouseover** haciendo lo que le indicamos, que en este caso fue mostrar una alerta.

Y Como anteriormente intuimos lo que pasaría por detras, en efecto fue así:

![injection](/assets/images/XSS/lab7/injection.png)

Y terminamos este laboratorio:

![end](/assets/images/XSS/lab7/end.png)

<br>

# Laboratorio 8: Stored XSS into anchor href attribute with double quotes HTML-encoded

En este laboratorio nos piden lo siguiente:

![lab8](/assets/images/XSS/lab8/lab8.png)

Podemos leer que nos dice que este laboratorio contiene un XSS almacenado(stored), y que este XSS se encuentra en la sección de comentarios.

Nos dice como objetivo que debemos hacer que al momento que al darle click al autor de un comentario, nos muestre una alerta.

Así que primero al entrar a la sección de comentarios vemos lo siguiente:

![comentarios](/assets/images/XSS/lab8/comentarios.png)

Podemos apreciar algunos comentarios, y también un apartado donde podemos publicar el nuestro, primero ingresaremos un comentario normal, para después revisar su comportamiento en el código de la web:

![comentar](/assets/images/XSS/lab8/comentar.png)

He dejado un comentario con esos datos, y se ve así al postearlo:

![prueba](/assets/images/XSS/lab8/prueba.png)

Así que al momento de leer el código de la web, vemos lo siguiente:

![codigo](/assets/images/XSS/lab8/codigo.png)

Podemos apreciar que hay diferentes elementos, como una imagen del usuario que hizo el comentario, nuestra referencia a la web dada en el comentario, y también el comentario obviamente.

<br>

Lo que me llama la atención es que cuando se esta pasando el valor de la página web del usuario que comenta, es que se ve que en el input hay un **href**, el cual contiene el valor de la web dada por el comentario, pero al parecer la entrada de datos no esta sanitizada.

Por lo que podriamos intentar inyectar código en lugar de proporcionar una web.

Así que probaremos lo siguiente en un nuevo comentario:

![comentario2](/assets/images/XSS/lab8/comentario2.png)

Podemos ver que en lugar de una web, hemos indicado que se ejecute la función **alert()** usando javscript:

```js
javascript:alert(1)
```

Así que al comentar esto, veremos el nuevo comentario:

![nuevo](/assets/images/XSS/lab8/nuevo.png)

Podemos ver que se agrego correctamente, y si esta parte de la web es vulnerable, entonces al darle click a nuestro nombre de autor marcado en morado, se supone que nos mostrará la alerta que inyectamos:

![uno](/assets/images/XSS/lab8/uno.png)

Y apreciamos que en efecto funciona nuestro XSS almacenado, ya que la entrada de datos en la parte de página web del autor no estaba bien sanitizada, por lo que al leer el código nuevamente, podemos apreciar lo siguiente:

![dan](/assets/images/XSS/lab8/Dante.png)

Vemos que se quedo almacenado el comentario junto a el XSS que creamos.

Así que hemos terminado este laboratorio:

![fin](/assets/images/XSS/lab8/fin.png)

<br>

# Laboratorio 9: Reflected XSS into a JavaScript string with angle brackets HTML encoded

En este laboratorio leemos lo siguiete:

![lab9](/assets/images/XSS/lab9/lab9.png)

Primero nos dice que este laboratorio con tiene una vulnerabilidad XSS Reflejada(reflected), y nos dice que la vulnerabilidad acontece en la función de busqueda al momento de ingresar datos en la busqueda.

Al entrar al laboratorio y buscar algo notamos lo siguiente:

![prueba](/assets/images/XSS/lab9/prueba.png)

Notamos que al ingresar a la web tenemos una entrada de datos, la cual llenamos con algun valor como "Prueba" en el campo de busqueda.

Así que al filtrar por esto en el código de la web, vemos lo siguiente:

![javascript](/assets/images/XSS/lab9/javascript.png)

```js
var searchTerms = 'Prueba';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
```

Podemos ver que se esta recibiendo el valor ingresado en la web, y se esta guardando en la variable **searchTerms**, sin embargo, si miramos bien, cuando se esta usando el metodo document.write, vemos que se esta pasando la variable **searchTerms** directamente a dicho metodo, así que esta manera no es muy segura de evitar XSS, ya que al tener acceso a la entrada de datos, que es la variable searchTerms, podríamos encontrar una forma de escapar de esa variable, inyectando nuestro código y lograr que el servidor lo interprete.

Para intentar escapar de esta variable, haremos uso de comillas simples, ya que como sabemos, la variable se esta guardando así:

`var searchTerms = 'Prueba';`

Y si nuestro valor en lugar de prueba es '-alert(1)-' entonces lo que estara pasando por detras es esto:

`var searchTerms = ''-alert(1)-';`

Vemos que la variable **searchTerms** obtuvo una cadena vacia, ya que la cerramos, y en su lugar inyectamos la alerta, y de esta forma estariamos escapando de la asignacion de variable, y como se esta pasando directamente a el metodo **document.write**, entonces esta vulnerabilidad se acontecera:

![alert](/assets/images/XSS/lab9/alert.png)

Vemos que ha funcionado, y al leer el código de la web:

![code](/assets/images/XSS/lab9/code.png)

Podemos apreciar que sucedio lo que esperabamos, logramos salir del valor de la variable para después meter nuestro propio código y que no forme parte del texto ingresado, así que habremos terminado este laboratorio:

![end](/assets/images/XSS/lab9/end.png)

<br>

# Laboratorio 10: DOM XSS in document.write sink using source location.search inside a select element

Nos dice que este laboratorio contiene una vulnerabilidad XSS en la función de verificar existencias de un producto.

Nos dice también que utlilza la función **document.write** de javascript para escribir datos en la página.

Y también que **document.write** maneja con datos que se sacan de **location.search** y saca valores de la petición que contiene parametros en la web, los cuales podemos manipular.

Y como objetivo nos pide escapar del valor del parametro inyectando nuestro código javascript que en este caso es una alerta.

<br>

Así que primero vamos a la función de verificar existencias de un producto, y vemos lo siguiente:

![funcion](/assets/images/XSS/lab10/funcion.png)


Podemos apreciar que al darle a **Check Stock** nos muestra el resultado de la función, más no lo que hay por detras, así que para esto interceptaremos la petición al momento de darle a ese boton, y veremos los siguientes datos en la petición:


![intercept](/assets/images/XSS/lab10/intercept.png)

Podemos apreciar en la petición que esta vez es por metodo POST, por lo que no veremos directamente en la URL los parametros asignados, si no que ahora los vemos en la petición como vemos en la imagen, vemos que hasta abajo estan los parametros:

`productId=1&storeId=London`

Así que usando el inspector de elementos del navegador buscamos esos parametros y encontramos el primero que es **productId**:

![pid](/assets/images/XSS/lab10/productid.png)

Pero viendo su código no encontramos algo interesante, ya que no se usa para algo más ese parametro, ni se llama en alguna otra función así que pasaremos al siguiente.

Y en el que encontramos algo interesante fue en el de **storeId**:

![js](/assets/images/XSS/lab10/js.png)

```js
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
  document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
  if(stores[i] === store) {
      continue;
  }
  document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

Lo que hace este código es lo siguiente:

Primero crea un arreglo llamado **stores**, el cual contiene los valores "London", "Paris" y "Milan".

Después en la segunda linea del código se esta creando una variable llamada **store**, la cual hace que obtengamos el valor del parametro **storeId**, por ejemplo si el valor del parametro **storeId** es "London", entonces la variable **store** valdra "London".

En la tercerea linea usamos **document.write()** para empezar a escribir datos en el código de la web actual, y lo primero que escribimos es la etiqueta **"<select name="storeId">"**.

Esto lo que hará es que primero la etiqueta **"<select>"** sirve para crear un menú desplegable en el cual los usuarios pueden elegir una opción y estas opciones se deben definir, y lo que esta dentro de esta etiqueta que es el **name** con el valor **"storeId"**, lo que esta haciendo aqui es que crea un nombre de control, y con nombre de control se refiere a crear un parametro por el cual cuando el usuario eliga su opción, entonces ese parametro **storeId** tomara el valor del elemento seleccionado del menú desplegable, y dejamos la etiqueta **"<select>"** sin cerrar para ir agregando opciones que el usuario pueda elegir en el menú desplegable.

En la cuarta linea, estamos usando un if, para comprobar si el parametro **store** tiene contenido, y en caso de tenerlo, entra a el if.

En la quinta linea se llama a otra función para escribir en el código de la web **document.write()**, y lo que escribimos es lo siguiente: `<option selected>'+store+'</option>` y lo que hace la etiqueta **<option>** es agregar una opción al menú desplegable, pero como estamos usando el atributo **selected** , esto quiere decir que el valor que le pasemos será el que se posicionara en primer lugar por defecto seleccionado en la web, y ese valor es **store**, el cual contiene el valor pasado por el parametro en la petición, y cerramos la opción con **</option>**.

Y por último, lo que hace el resto del código es que crea un bucle for, el cual recorre cada valor del arreglo **stores**, y compara si el valor actual de **stores** es igual al valor pasado por el parametro **store**, y si es igual entonces se omite esta parte, pero en caso de que el valor actual de **stores** no sea igual al de **store** entonces este valor se agregará a la lista usando **document.write()** con el elemento actual a agregar, de esta manera evitamos duplicados en el menú desplegable.

Y por último se cierra el menú desplegable.

<br>

Pero este código, no es tan seguro, ya que es vulnerable a XSS gracias a un **document.write()** mal configurado.

En la siguiente linea del código:

```js
document.write('<option selected>'+store+'</option>');
```

Lo que sucede aquí, es que al momento de que se pasa el valor **store**, se está pasando directamente del parametro, sin antes validarlo para evitar ataques XSS, así que como no se esta sanitizando la entrada de dicho valor, entonces el atacante podría meter código malicioso, con la intencion de escapar de donde se esta agregado este valor, y agregar nuestro propio código malicioso.

Como recordamos en el intercept, vimos que en la consulta se usan los 2 siguientes parametros:

```js
productId=1&storeId=London`
```

Como recordamos, al leer el código vemos que el parametro **storeId** es el potencial peligro, ya que tenemos acceso a la entrada de datos, y como recordamos que encontramos un error de sanitizacion en el código entonces podemos intentar lo siguiente.

En el código de la web vemos lo siguiente:

![list](/assets/images/XSS/lab10/list.png)

Podemos ver que en esta parte se interpreto todo lo del script explicado anteriormente, pero podemos ver que en la linea:

```js
<select name="storeId">
```

Aquí es donde se usa el valor del parametro **storeId**, y lo que le hayamos pasado llegará aquí, así que nosotros en la URL agregaremos manualmente el valor del parametro **storeId**, para agregar manualmente el valor del **storeId** desde la URL, haremos lo siguiente:

`https://0a94008f046e446783b94d3b004b00d6.web-security-academy.net/product?productId=1&storeId=Test`

Vemos que usando el simbolo &, indicamos que hay otro parametro el cual es **storeId**, el cual le asignamos el valor **"Test"**.

Y como recordamos en el código, lo que este en este parametro **storeId** será el valor que se pondrá como predeterminado, así que al tramitar esa URL vemos en la web lo siguiente:

![test](/assets/images/XSS/lab10/test.png)

Podemos apreciar que en la lista desplegable de abajo, el valor que indicamos en el parametro **storeId** es el que se puso por defecto, dejando a las demas opciones debajo de ellas por si el usuario quiere elegirlas.

Así que de esta forma, sabemos que podemos meter datos ahí, y en este caso en lugar de meter un texto, meteremos código javascript malicioso:

`https://0a94008f046e446783b94d3b004b00d6.web-security-academy.net/product?productId=1&storeId="></select><img src=noexiste onerror=alert(1)>`

De esta forma, primero usamos **">** para escapar del valor de nombre por defecto, de esta forma se cierra el texto y la etiqueta **<option>**.

Después usamos **</select>** para cerrar la etiqueta que permite crear un menú desplegable, y una vez cerrado y estamos libres de etiquetas, entonces solo queda provocar la invocacion del código usando **<img src=noexiste onerror=alert(1)>**que como ya sabemos, de esta forma podemos llamar a una imagen que no existe para pasar directo a la ejecución en caso de error y que se ejecute lo que deseamos, en este caso una alerta.

Y al ejecutar esto:

![alert](/assets/images/XSS/lab10/alert.png)

Podemos ver que ha funcionado!

Y podemos ver nuevamente en el código de la web para entender un poco mejor lo que sucedio:

![code](/assets/images/XSS/lab10/code.png)

Primero, podemos ver que en el código, después de que se paso de la función de javascript que explicamos, vemos que llega aqui nuestro valor que definimos en el parametro **storeId**, que en este caso fue la inyección de código anterior.

Primero lo que sucedio como vemos en la linea que esta marcada en azul en la imagen anterior, es que usamos **">** para escapar de ese valor que como recordamos ahí se define el valor por defecto del menú desplegable dependiendo del valor que pongamos en el parametro **storeId** lo pondrá.

Y como escapamos de eso, lo que hicimos fue usar **</select>**, que como ya sabemos fue para escapar del menú desplegable, y ahora que no estamos dentro de etiquetas lo que haremos es meter nuestro código que ya sabemos es **<img src=noexiste onerror=alert(1)>**.

> Si te confunde el formato tal vez sea porque esto se ordena automaticamente en este formato de código como se ve en la imagen pero la lógica no cambia ya que solo se ordena automaticamente.

Y habremos terminado este laboratorio:

![end](/assets/images/XSS/lab10/end.png)

<br>