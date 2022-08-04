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

Debemos recordar que una tabla en **MySQL** se conforma por partes:

![Tabla](/assets/images/SQLi/tabla.png "Imagen de TryHackMe")

Vemos que está conformada por filas y columnas, debemos saber esto, ya que lo necesitaremos más adelante.
