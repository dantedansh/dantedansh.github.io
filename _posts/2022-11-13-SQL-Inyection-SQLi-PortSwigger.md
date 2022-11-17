---
layout: single
title: Inyección SQL - SQLi
excerpt: "Explicación de como resolver los laboratorios de PortSwigger sobre SQL inyection SQLi."
date: 2022-11-13
classes: wide
header:
  teaser: /assets/images/SQLiPortswigger/SQLips.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - vulnerabilidad web
tags:  
  - mysql
  - SQLi
  - Portswigger
---

# Laboratorio 1: vulnerabilidad de inyección SQL en la cláusula WHERE que permite la recuperación de datos ocultos

<br>

En este primer laboratorio, veremos algo básico, como ya hemos visto en el titulo, jugaremos con la cláusula **WHERE** para recuperar datos de las tablas dentro de la base de datos.

![Lab1](/assets/images/SQLiPortswigger/lab1/Lab1.png)


<br>



Como vemos en la imagen esto es lo que nos muestra en el laboratorio 1, nos dice que este laboratorio contiene una vulnerabilidad tipo SQL inyection, en el filtro de la categoria producto, y cuando hacemos una peticion sobre alguna categoria, en este caso usaremos la categoria "gifts" y por detras se interpreta una consulta que es así:

`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

Que como ya sabemos, primero se selecciona todo el contenido de la tabla **products**, para desupes filtrar datos donde **category** tenga un valor en formato string el cual es **Gifts**, y por ultimo nos dice que **relased**, debe ser igual a 1.

Este ultimo nombre **released**, nos da a entender que hay más datos que no podemos ver ya que como sabemos relased significa "liberado", por lo que debe haber cosas que aún no se han liberado, y por logica deben tener un valor que no sea 1, para que no se muestren antes de tiempo.

<br>

Ahora que conocemos un poco la consulta vayamos a desplegar el laboratorio en el boton que dice "Acces the lab".

Una vez dentro nos encontraremos con esta página que nos desplega el laboratorio:

![Lab1](/assets/images/SQLiPortswigger/lab1/web1.png)

<br>

Vemos que al parecer es un tipo de tienda online, arriba hay un indicador que nos dice si hemos terminado el laboratorio o no, y ya de primera vista estamos viendo un filtro de categorias:

![Lab1](/assets/images/SQLiPortswigger/lab1/categories.png)

<br>

Como la categoria que nos dijeron al inicio, así que ya tenemos por donde empezar!

