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

