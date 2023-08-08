---
layout: single
title: Introducción a Linux (Completo).
excerpt: "Introducción completa para comenzar a usar sistemas GNU/Linux."
date: 2023-08-08
classes: wide
header:
  teaser: /assets/images/Linux/Linux.jpg
  teaser_home_page: true
#  icon: /assets/images/hackthebox.webp
categories:
  - Linux
tags:  
  - Bash
---

<br>

En este post iré explicando lo fundamental que necesitas saber sobre linux, hasta cosas más avanzadas como bash scripting.

# Comandos básicos linux

## whoami

`whoami` : Este comando nos sirve para saber que usuario esta usando el sistema actualmente.

![whoami](/assets/images/Linux/comandos_basicos/whoami.png)

Podemos ver que el usuario que esta ejecutando el sistema actualmente es d4nsh.

----

## id, sudo su, exit

`id` : Este comando nos permite ver los grupos a los que el usuario esta integrado:

![whoami](/assets/images/Linux/comandos_basicos/id.png)

Podemos apreciar que pertenecemos a toda esta serie de grupos, cada usuario tiene un grupo con su mismo nombre, pero ademas contiene otros grupos a los que puede ser añadidos.

Existen grupos que son potencialmente peligrosos si es que no se configuran adecuadamente y se les otorga el grupo a un usuario atacante, entonces este atacante podría escalar privilegios, que básicamente es llegar al usuario root, el usuario root es el que tiene permitido hacer la mayoría de cosas en el sistema, siendo algo así como un usuario administrador.

si vemos bien, apreciamos que estamos dentro del grupo (root), por lo que al ejecutar el comando:

`sudo su` : Podremos migrar al usuario con máximos privilegios siempre y cuando conozcamos la contraseña.

![whoami](/assets/images/Linux/comandos_basicos/root.png)

Podemos ver que migramos al usuario root, y dentro de este usuario root, tenemos acceso a esos grupos que se ven en la imagen.

Con el comando `exit` podemos salir de la sesión de root para volver a la anterior, en este caso d4nsh:

![whoami](/assets/images/Linux/comandos_basicos/migracion.png)

> El usuario root comúnmente tiene un identificador que lo caracteriza y es el símbolo de #.

> Al momento de entrar a root y salir con exit sin cerrar la terminal, puedes volver a poner el comando `sudo su` para migrar nuevamente a root pero esta vez no te pedirá contraseña ya que por detrás se almacena un token temporal por cierto tiempo el cual evita que tengamos que poner la contraseña a cada rato, pero puede ser peligroso si no cierras la terminal ya que otra persona podría poner el comando y migrar a root, por eso es importante que al terminar cierres tu terminal y al momento de abrir otra y querer migrar a root, nuevamente te pedirá la contraseña.

Y si quieres ejecutar solo un comando en el contexto de root, pero no tienes la necesidad de migrar a root para ejecutar este comando como root.

Podemos usar el comando `sudo` antes del comando que queremos ejecutar como root, por ejemplo tenemos una terminal como el usuario d4nsh, pero si queremos ejecutar el comando `whoami` con privilegios de root entonces sucederá lo siguiente:

![whoami](/assets/images/Linux/comandos_basicos/root-context.png)

Podemos apreciar que ejecutamos el comando `whoami` en el contexto del usuario root, pero seguimos siendo d4nsh ya que solamente ejecutamos el comando anterior con contexto de root más no nos convertimos en root.

----

## Rutas de los grupos, cat

Los grupos mostrados anteriormente existen en rutas del sistema, existen dentro de la ruta del sistema **/etc/**  y dentro de esta ruta existe un archivo llamado **group**.

`cat` El comando cat se utiliza para leer archivos de texto o similares, por ejemplo si queremos leer el archivo anterior tendríamos que ejecutar:

`cat /etc/group` Aquí estamos diciendo que nos lea el contenido del archivo **group** que se encuentra dentro de la ruta **/etc/**:

![whoami](/assets/images/Linux/comandos_basicos/grupos.png)

Podemos apreciar que todos estos grupos son los que existen dentro del sistema, son el total de todos los que hay, así que de esta forma podemos leer archivos con el comando cat.

> Se verá diferente si tienes tu sistema operativo linux sin modificar, pero el mio esta así gracias a unas configuraciones.

----

## Ruta absoluta y ruta relativa, which

Cada comando contiene una ruta absoluta y una ruta relativa, veamos el ejemplo con el comando `whoami` .

Al usar el comando `whoami` estamos llamando a ese comando desde su ruta relativa.

Y para ver su ruta absoluta usaremos el comando `which`:

![whoami](/assets/images/Linux/comandos_basicos/which.png)

Podemos apreciar que la ruta absoluta del comando whoami es la ruta: `/usr/bin/` y ejecuta el binario `whoami` que es la ruta donde se almacena el binario de este comando.

Un binario es un ejecutable que hace algo, en este caso sabemos que whoami nos muestra el usuario actual del sistema.

Ahora que ya sabemos la ruta absoluta de este binario, llamaremos a el comando whoami desde su ruta absoluta para ver que funciona:

![whoami](/assets/images/Linux/comandos_basicos/absoluta.png)

Esto es lo mismo que usar simplemente `whoami`, pero si lo llamamos desde toda su ruta entonces se esta llamando desde su ruta absoluta.

----

## Variable de entorno, $PATH, $HOME, echo

`echo` Este comando nos sirve para imprimir un mensaje en pantalla por ejemplo:

![whoami](/assets/images/Linux/comandos_basicos/echo.png)

Podemos ver que hemos mostrado el texto que pusimos entre comillas dobles y después nos lo mostró.

Ahora, ¿que es una variable de entorno?

Una variable de entorno es una variable que se puede encontrar dentro del sistema operativo y que podemos leer su contenido.

Por ejemplo, la variable PATH:

![whoami](/assets/images/Linux/comandos_basicos/path.png)

> Para imprimir el valor de una variable en bash, se utiliza el símbolo de dolar $ seguido de la variable a la que quieres leer sus datos, en este caso es la variable PATH.

Podemos ver que esta variable de entorno contiene una serie de rutas, estas rutas tienen la siguiente función:

Cuando ejecutas un comando con la ruta relativa,  este comando con ruta relativa, se empieza a buscar dentro de todos estos directorios que se ven en la imagen.

Empieza desde `/root/.local/bin` y sigue así buscando que exista ese binario dentro de todas las rutas que siguen, cada ruta se separa por ":" y sigue buscando hasta encontrarlo, cuando lo encuentra lo ejecuta.

Sabemos que la ruta absoluta de `whoami` esta dentro de `/usr/bin`, entonces al momento de llamar el comando `whoami` sin ruta absoluta, solamente relativa, entonces este comando buscara por cada directorio, y como vemos en la imagen en la quinta posición esta la ruta donde se encuentra el binario de whoami, por lo que lo encontrará y lo ejecutará.

> También existe una forma de hackear una maquina si en el sistema hay un script o algo similar al que tengamos acceso y si se esta usando comandos con ruta relativa puede haber un riesgo de seguridad que veremos más adelante.

Y la variable de entorno `HOME` nos indica cual es nuestro directorio personal del sistema, que podemos verlo usando `echo` a esa variable de entorno:

![whoami](/assets/images/Linux/comandos_basicos/casa.png)
> Esta ruta es donde el sistema nos pone por defecto al abrir una terminal, más adelante veremos sobre estas rutas.

----

## grep, pipes

El comando `grep` nos es muy útil al momento de querer filtrar información, por ejemplo, si hacemos un cat al archivo `/etc/group`:

![whoami](/assets/images/Linux/comandos_basicos/grupos.png)

Vemos este contenido, pero si solamente queremos ver algo en especifico, por ejemplo el grupo que se llama floppy, entonces aquí es donde entra el uso de pipes y grep.

Los pipes o tuberías nos sirven para que la salida de un comando se guarde dentro del pipe para después tratar esa salida y hacerle lo que le indiquemos.

Por ejemplo:

![whoami](/assets/images/Linux/comandos_basicos/grep.png)

Podemos ver que la salida del comando `cat /etc/group` se almacena dentro del pipe que se representa con este carácter: `|` , dentro de esa tubería se guarda la salida del cat para después usar el siguiente comando, el cuál es `grep` y lo que hace grep es filtrar datos de una salida de datos dada, en este caso esa salida de datos dada es la que esta almacenada en el pipe que es todo el texto que esta dentro de `/etc/group` y que estamos leyendo con cat.

Entonces ponemos como parámetro al comando `grep`  la palabra a filtrar, en este caso queremos que nos filtre lo que contenga la palabra "floppy", y en la salida del comando podemos ver que nos da una linea de salida filtrandonos solo ese elemento y ignorando el resto ya que solo queremos filtrar las cosas que contengan ese valor en la linea.

## parámetro -n de grep

el parámetro `-n` del comando grep, nos sirve para indicarnos en que linea del archivo pasado se encuentra el valor que filtramos, por ejemplo:

![whoami](/assets/images/Linux/comandos_basicos/-n.png)

Podemos apreciar que nos muestra que esta en la linea 19, y podemos comprobar que es verdad:

![whoami](/assets/images/Linux/comandos_basicos/19.png)

<br>

# Segunda parte de comandos básicos en Linux

## command -v

Como recordamos en el post anterior, vimos el uso del comando `which` para saber la ruta absoluta de un comando, pero también nos puede servir para verificar si existe cierto comando, por ejemplo si ponemos algo que no existe nos mostrara esto:

![whoami](/assets/images/Linux/comandos_basicos/notfound.png)

Podemos ver que queremos ver la ruta absoluta de noexiste pero obviamente ese comando no existe, por lo que nos responde con la salida: "noexiste not found".

De esta forma podemos saber si existe un comando o no dentro de un sistema, pero también podemos usar el comando: `command -v whoami` :

![whoami](/assets/images/Linux/comandos_basicos/alternativa.png)
Esto es una alternativa en caso de que el binario de whoami no exista en el sistema y queramos saber si existen otros binarios, vemos que también nos dice su ruta absoluta.

##  pwd, ls

El comando `pwd` nos sirve para saber en que directorio estamos actualmente:

![whoami](/assets/images/Linux/comandos_basicos/pwd.png)

Podemos ver que estamos dentro de la ruta `/home/dansh`

`ls` : El comando ls nos sirve para listar los directorios y archivos de una ruta.

si usamos solo el ls a secas veremos los directorios y archivos de la ruta actual:

![whoami](/assets/images/Linux/comandos_basicos/ls.png)

Podemos ver que hay 12 carpetas dentro de la ruta actual en la que estamos.

También podemos listar archivos no solo de la ruta actual si no también de la ruta que le indiquemos, por ejemplo queremos listar lo que hay dentro de la carpeta `/home/`

![whoami](/assets/images/Linux/comandos_basicos/ls-home.png)

Y podemos ver que dentro de esa ruta existe la carpeta d4nsh.

## Parámetros de ls:

`-l` nos sirve para mostrar lo mismo que lo anterior pero con más detalles, como los permisos, propietario y grupo, etc:

![whoami](/assets/images/Linux/comandos_basicos/ls-l.png)

`-la` : Este parámetro nos sirve para listar directorios y archivos pero también nos listará los que están ocultos:

![whoami](/assets/images/Linux/comandos_basicos/ls-la.png)

> En linux los elementos ocultos inician con un punto, por ejemplo: .datos

## cd y manejo de directorios

`cd` : Este comando nos sirve para entrar dentro de un directorio especifico, por ejemplo, hacemos un ls para listar los archivos del directorio actual:

![whoami](/assets/images/Linux/comandos_basicos/ls.png)

Y con el comando `cd` queremos entrar a la carpeta que se llama "Imágenes", entonces haremos lo siguiente:

![whoami](/assets/images/Linux/comandos_basicos/cd.png)

Podemos apreciar que entramos a esa carpeta, después usamos pwd para que vean que si estamos en la ruta de Imágenes, y por último hice un ls para ver que había dentro de ese directorio actual, en este caso hay otra carpeta llamada wallpapers.

Y en este caso estamos en la ruta de Imágenes, pero si queremos volver un directorio atrás , osea llegar al directorio d4nsh, entonces usaremos:

`cd ..` : Con este comando retrocederemos un directorio hacía atrás:

![whoami](/assets/images/Linux/comandos_basicos/cd...png)

Podemos apreciar que después de retroceder un directorio usamos el comando pwd para confirmar que hemos retrocedido un directorio.

Ahora si queremos retroceder más de un directorio podemos usar lo mismo pero indicando las veces que queremos ir para atrás, supongamos que queremos ir más atrás de la carpeta d4nsh y la carpeta home, entonces usaríamos:

`cd ../../`

De este modo cada 2 puntos y barra inversa estamos retrocediendo un directorio, en este caso estamos retrocediendo dos, y nos deja en el siguiente directorio:

![whoami](/assets/images/Linux/comandos_basicos/raiz.png)

Podemos apreciar que detrás de esos 2 directorios que recorrimos hacía atrás existe uno que simplemente es el signo de barra inversa / , y esto es un directorio , es la raíz del sistema, ya no hay nada más atrás de este directorio, así que si hacemos un ls como en la imagen podemos ver que hay ciertos archivos del sistema y directorios.

Ahora si queremos ir a un directorio que esta dentro de otro y dentro de ese hay otro y así sucesivamente, entonces podemos hacer lo siguiente:

`cd /home/d4nsh/Imágenes/` : Con este comando estamos viajando hasta la carpeta Imágenes ya que esa es su ruta absoluta, y si ejecutamos ese comando iremos a la ruta:

![whoami](/assets/images/Linux/comandos_basicos/regreso.png)

Podemos apreciar que hemos viajado hacía esta ruta nuevamente.

Al abrir una terminal, por defecto apareceremos en la ruta `/home/d4nsh/` ya que es la ruta por defecto donde esta lo necesario para el usuario, cada usuario tiene asignado una carpeta dentro del directorio `/home/`.

Y si estamos dentro de una ruta por ejemplo en la de imágenes, y hacemos el comando `cd` a secas, entonces esto nos llevará a la misma ruta que nos lleva el sistema por defecto al abrir una terminal, osea en `/home/d4nsh`:

![whoami](/assets/images/Linux/comandos_basicos/default.png)

## Manejo de rutas y TAB

Una vez entendimos un poco el funcionamiento del comando `cd` toca ir a explicar unas cuantas cosas más.

Digamos que estamos en la siguiente ruta:

![whoami](/assets/images/Linux/comandos_basicos/descargas.png)

Y deseamos viajar a la carpeta `Imágenes` pero queremos ir de una forma más rápida y no tener que escribir todo desde `/home/d4nsh/Imágenes` , entonces lo que podemos usar en este caso para resumir el directorio por defecto que es `/home/d4nsh` podemos usar esto: `~/`

Este símbolo ~ representa a la ruta por defecto del sistema que es la carpeta home de nuestro usuario, por ejemplo:

![whoami](/assets/images/Linux/comandos_basicos/home.zip.png)

Podemos ver que viajamos a Imágenes usando el comando cd y usamos el símbolo `~` que es lo mismo que `/home/d4nsh` y ahora nos facilita el trabajo de no tener que escribir toda la ruta de home de nuestro usuario.


## Auto-completado de rutas con TAB

Otra cosa que nos será muy útil para ahorrar tiempo viajando dentro de rutas es que podemos usar la tecla de TAB para auto-completar la ruta a la que queremos ir, por ejemplo escribimos: `cd /home/d4` y al dar a la tecla de TAB esta nos auto-completará el resto que es nsh, y nos lo agrega  ya que eso es lo único que empieza con d4, si hubiera otro directorio que empiece con d4 entonces tendrías que agregar más letras hasta que haya una diferencia y el único que quede sea el directorio al que quieres ir.

O otro modo es presionar TAB multiples veces ya que de esa forma se irá poniendo automáticamente todas las rutas dentro de la ruta a la que estas apuntando y si no es una vuelves a pulsar TAB para que se cambie por la que sigue y si no es esa nuevamente pulsas TAB hasta llegar a la que deseas.

----

## Identificador de usuario e identificador de grupo

Cada usuario tiene asignado un grupo, y ese grupo tiene un valor numérico que es un identificador y también el usuario tiene un identificador.

El identificador del usuario se le llama `uid`
El identificador del grupo se le llama `gid`

Dentro del archivo `passwd` que se encuentra en la ruta de `/etc/` dentro de ese archivo llamado passwd, podemos ver los usuarios existentes en el sistema al igual que sus **uid**, y **gid**, hagamos lo siguiente:

![whoami](/assets/images/Linux/comandos_basicos/uid-gid.png)

Estamos como ya sabemos, leyendo el contenido del archivo `/etc/passwd` después esos datos se pasan al pipe y grep toma esa salida de datos para filtrar por el valor "d4nsh" y nos muestra el resultado de las lineas que contienen ese valor.

Podemos ver que esta nuestro nombre, seguido de una x que es el valor de la contraseña pero después explicaremos bien esa parte, después esta un valor el cual es el 1000, y otro el cual es el 1003 y también vemos el nombre del propietario y su ruta personal home, también seguido de que tipo de shell/terminal usa, en este caso uso una zsh pero podría ser una bash o cualquier otra.

Estos valores son los del **uid** y **gid**, ya que si recordamos el comando id para ver los grupos veremos lo siguiente:

![whoami](/assets/images/Linux/comandos_basicos/id.png)

Podemos apreciar que el identificador de usuario es el 1000 que es d4nsh, y el identificador de grupo que es 1003 que igual es d4nsh ya que cada usuario tiene un grupo con su nombre.

----

## Migración de shell

Existe una variable de entorno llamada `SHELL` la cuál nos indica que tipo de shell esta ejecutando nuestro usuario:

![whoami](/assets/images/Linux/comandos_basicos/zsh-shell.png)

Podemos apreciar que estamos usando una shell la cuál es ZSH, pero hay un archivo donde están todas las shell que están disponibles en nuestro sistema, este archivo esta en `/etc/shells`:

![whoami](/assets/images/Linux/comandos_basicos/shells.png)

Podemos ver que hay unas cuantas, nuestra shell por defecto como vimos es ZSH pero la tuya podría ser una de estas, si queremos migrar a alguna por ejemplo quiero pasar de zsh a bash podemos usar simplemente el comando `bash`, podemos ver que bash esta dentro de `/bin/bash` y como en la variable de entorno `PATH` recordamos que esta la ruta `/bin/`:

![whoami](/assets/images/Linux/comandos_basicos/path.png)

Podemos apreciar, que esta en la sexta posición, por lo que al ejecutar su ruta relativa podremos acceder:

![whoami](/assets/images/Linux/comandos_basicos/migrar.png)

Podemos ver que hemos cambiado de shell a una bash.

> Para volver a tu shell por defecto simplemente usa el comando exit.

<br>

# Operadores lógicos , control del flujo (stdout y stderr) y procesos en segundo plano

---

## Concatenación de comandos

Existe una forma de concatenar comandos para ejecutar 2 o más comandos en una sola linea (one liner), por ejemplo si queremos ejecutar el comando `whoami` y también el comando `ls` en una sola linea podemos concatenar ambos usando el punto y coma `;` como podemos ver:

![whoami](parte3-imagenes/concatenados.png)

Podemos ver que nos dio el output de los 2 comandos.

> El output significa la salida de los comandos que hemos ejecutado que se muestran en pantalla.

Podemos ver que primero nos dio el output del comando whoami seguido del comando ls.

Si ponemos un comando que no existe concatenado con uno que si existe sucederá esto:

![whoami](parte3-imagenes/error.png)

Podemos ver que el comando "whoa" no existe, pero aún así si ejecuto el ls ya que ese comando si existe, y vemos que en el output nos da un error en la salida del comando whoa, ya que no existe y nos dice que el comando no ha sido encontrado.

> Cuando recibes un error en pantalla como el del comando whoa se le denomina stderr, ya que significa que hubo un error, por el contrario si todo es exitoso se le denomina stdout a la salida de tu comando como en este caso lo es el ls.

----

## Ver códigos de estados de un comando o proceso

Cada que ejecutamos un comando, ya sea que haya sido exitoso o no, siempre por detrás se genera un código de estado ante el último comando ejecutado.

Los más comunes son los siguientes:

| Valor de estado | significado                                                                                       |
|-----------------|---------------------------------------------------------------------------------------------------|
| 0               | Indica que la ejecución del comando o proceso se ha realizado con éxito.                          |
| 127             | Este estado significa cuando el comando dado no existe en la ruta de la variable de entorno PATH. |
| 1               | Indica que el proceso tuvo un error y nos ha mostrado una alerta sobre ese error.                 |

Hagamos unas pruebas con cada uno de estos estados de respuesta.

Primero ejecutaremos un comando que sea exitoso, osea que lo que hayamos ejecutado se haya realizado con éxito y como debe ser, por ejemplo un simple `ls`:

![whoami](parte3-imagenes/0.png)

Después de ejecutar el ls, podemos ver que ejecutamos `echo $?` esto nos sirve para imprimir el estado que tuvo la ejecución anterior, en este caso podemos ver un valor 0 por lo que se ha realizado con éxito.

Pero por otro lado si llamamos a un comando que no existe y mostramos el estado:

![whoami](parte3-imagenes/127.png)

Podemos apreciar que nos ha respondido el valor 127 que como sabemos, indica que el comando no existe dentro de la variable de entorno PATH.

![whoami](parte3-imagenes/1.png)

Podemos apreciar que intentamos leer el contenido de un archivo que no existe y su respuesta de estado fue 1, que como sabemos indica que ha habido un error con alerta.

----

## Operadores lógicos

Existen varios tipos de operadores lógicos en linux, veamos cuales son:

| Operador lógico | significado                                                                                                                                                                                                                                                                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| &&              | Este operador "AND" significa que si ambas expresiones son verdaderas entonces nos devuelve un valor positivo (true), y si alguna de las 2 expresiones no se cumple entonces devolverá un estado de error (false).                                                                                                                                                |
| \|\|            | El operador "OR" significa que aunque una de las 2 expresiones sea falsa, mientras una sea verdadera este se ejecutará sin problemas, dando 2 opciones a elegir, en caso de que la primera no se cumpla, tomara la segunda, que en caso de cumplirse devolverá un estado de respuesta verdadero (true), y obviamente si ninguna es verdadera devolverá un false. |
| !               | Y este operador no se usará por ahora ya que se toca en otros temas pero significa que si al evaluar las operaciones osea las expresiones, si esto da falso, entonces esto responderá con un estado verdadero, esto es para asegurarse de que algo no se este cumpliendo por cualquier motivo necesario, pero esto se verá después.                                                                                                                                                                                                                                                                                                                                                                 |

Para entender mejor los primeros 2 operadores veamos ejemplos:

### ejemplo del operador AND

![whoami](parte3-imagenes/y.png)

Podemos ver que en la primera ejecución pusimos `whoami && ls` y como ambas expresiones son verdaderas ya que existen en el PATH, entonces se ejecutará la acción, en este caso es la ejecución del comando.

Pero si vemos abajo si desde un inicio la primera expresión es falsa, ambas se tomaran como falsas y no ejecutarán su función.

### Ejemplo del operador OR

![whoami](parte3-imagenes/o.png)

Podemos apreciar en la imagen que aunque la primera expresión no exista en el PATH la cual es en este caso "wh" , vemos que como la primera expresión no existe, entonces paso a la siguiente y la ejecuto aunque no existiera la primera expresión.

Y en la segunda ejecución vemos que siempre tomará la primera expresión pero en caso de no existir pasará a la segunda para comprobar si esa otra opción existe.

----

## Control de flujo stdout y stderr

### stderr:

Al ejecutar un comando, o una instrucción que genere un error como por ejemplo, intentaremos leer un archivo que no existe:

![whoami](parte3-imagenes/stderr.png)

Podemos ver que por debajo se manifiesta el mensaje de error que se le conoce como stderr ya que nos esta mostrando una salida con un mensaje erróneo.

Pero podemos ocultar esto en caso de que nos sea molesto y queramos omitir esta salida de error aunque el comando no haya sido exitoso por cualquier motivo.

Para esto usamos el control de flujo, el stderr se identifica en su control de flujo como el valor numérico 2.

Entonces podemos hacer lo siguiente:

![whoami](parte3-imagenes/2.png)

Podemos apreciar que al ejecutar esto ya no nos mostró el aviso y en la segunda ejecución podemos ver que aunque fue un estado de error, ya no nos mostró ningún aviso de error en la pantalla, y esto fue porque redirigimos la salida del error hacía la ruta `/dev/null`.

La ruta `/dev/null` es una ruta del sistema donde todo lo que se meta dentro de esa ruta será eliminado permanentemente, es algo así como un agujero negro dentro del sistema.

Vemos que usamos `2>/dev/null` después de el comando, y esto se hace para como dijimos redirigir el stderr hacía esa ruta y sea desaparecida sin verla en pantalla en ningún momento a pesar de que no haya sido una ejecución exitosa.

El número 2 indica que la salida en caso de ser errónea, entonces será redirigida a el `/dev/null` pero usamos el símbolo de mayor que `>` para redirigir el estado de error osea el 2 a la ruta > /dev/null.


### stdout:

De igual manera que el error, también podemos redirigir la salida de un comando exitoso.

![whoami](parte3-imagenes/1.1.png)
> Es exitoso ya que el archivo que intentamos leer si existe, pero no queremos ver su salida.

Podemos apreciar que es lo mismo pero simplemente cambio el valor de 2 a 1 que el 1 significa stdout, salida exitosa.


## redirigir ambos flujos a la vez

Ahora si queremos ocultar el estado stdout, y el stderr a la vez, haremos lo siguiente:

![whoami](parte3-imagenes/ambos.png)

Podemos apreciar que usando: `&>/dev/null` tanto de forma exitosa y no exitosa pudimos ocultar ambos casos.

Y lo que hacemos aquí es que simplemente redirigimos las 2 salidas a la ruta que ya sabemos /dev/null/ para desaparecer cosas.

## ¿Para que ocultar el flujo de algo?

Puede que te estés preguntando esto ya que por el momento no parece tener sentido, pero pongamos un ejemplo sencillo.

Al abrir un programa por ejemplo:

![whoami](parte3-imagenes/telegram.png)

En este caso estamos abriendo telegram desde la terminal y vemos muchas advertencias pero nosotros no queremos ver esto, por lo que podemos redirigir esto para tener la terminal limpia:

![whoami](parte3-imagenes/telegramlimpio.png)

Podemos apreciar que al redirigir el flujo ya no nos muestra nada y es más cómodo estar así , pero obviamente tiene muchas funciones mejores que estas, esto solo fue un simple ejemplo.

Por ejemplo algo más extenso sería al momento ya de programar scripts en bash y requieras la ejecución de ciertos programas, comandos, etc. Entonces será muy útil esto para no llenar la pantalla de quien ejecuta el script haciendo que tenga un mal aspecto.

## procesos en segundo plano

Como en el ejemplo anterior vimos que al abrir un programa o algún proceso por terminal esta se queda en espera, se quedará así a menos que cierres la terminal pero si la cierras se cerrara también el programa que haz abierto con ella.

Para solucionar esto podemos optar por poner el proceso en segundo plano.

![whoami](parte3-imagenes/id.png)

Podemos ver que al final de la ejecución del programa pusimos un símbolo de &, y este símbolo al final de un proceso indica que lo que se va a ejecutar se haga en segundo plano, y podemos ver que nos lanza un numero que es un identificador llamado "pid" process id, el cuál se le asigno a el proceso que se abrirá en segundo plano.

Pero aún hecho esto si cerramos la terminal se cerrara el programa que abrimos con el ya que el programa aún depende de la terminal, pero para hacerlo independiente usaremos el comando `disown` para hacer independiente el proceso anterior:

![whoami](parte3-imagenes/disown.png)

Y de esta forma podremos cerrar la terminal sin perder el programa abierto ya que ya no depende de la terminal.

> Esta no es la manera más recomendada de ejecutar programas en linux, ya que se puede facilitar simplemente ejecutándolos desde el menú de apps o desde un atajo de teclado si es que usas bspwm o algún parecido, pero explico esto ya que es muy importante para cuando profundicemos más.
