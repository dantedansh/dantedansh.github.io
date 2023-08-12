---
layout: single
title: Introducción a Linux (Completo).
excerpt: "Introducción completa para comenzar a usar sistemas GNU/Linux."
date: 2023-08-08
classes: wide

toc: true
toc_label: "Contenido del post"
toc_icon: "book"
toc_float: "true"

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

# Comandos basicos linux

## whoami

`whoami` : Este comando nos sirve para saber que usuario esta usando el sistema actualmente.

![whoami](/assets/images/Linux/comandos_basicos/whoami.png)

Podemos ver que el usuario que esta ejecutando el sistema actualmente es d4nsh.

---

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

---

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

---

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

---

## parametro -n de grep

el parámetro `-n` del comando grep, nos sirve para indicarnos en que linea del archivo pasado se encuentra el valor que filtramos, por ejemplo:

![whoami](/assets/images/Linux/comandos_basicos/-n.png)

Podemos apreciar que nos muestra que esta en la linea 19, y podemos comprobar que es verdad:

![whoami](/assets/images/Linux/comandos_basicos/19.png)

<br>

---

# Segunda parte de comandos basicos en Linux

Ahora toca ver más comandos Básicos:

## command -v

Como recordamos en el post anterior, vimos el uso del comando `which` para saber la ruta absoluta de un comando, pero también nos puede servir para verificar si existe cierto comando, por ejemplo si ponemos algo que no existe nos mostrara esto:

![whoami](/assets/images/Linux/comandos_basicos/notfound.png)

Podemos ver que queremos ver la ruta absoluta de noexiste pero obviamente ese comando no existe, por lo que nos responde con la salida: "noexiste not found".

De esta forma podemos saber si existe un comando o no dentro de un sistema, pero también podemos usar el comando: `command -v whoami`:

![whoami](/assets/images/Linux/comandos_basicos/alternativa.png)
Esto es una alternativa en caso de que el binario de whoami no exista en el sistema y queramos saber si existen otros binarios, vemos que también nos dice su ruta absoluta.

## pwd, ls

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

---

## Parametros de ls

`-l` nos sirve para mostrar lo mismo que lo anterior pero con más detalles, como los permisos, propietario y grupo, etc:

![whoami](/assets/images/Linux/comandos_basicos/ls-l.png)

`-la` : Este parámetro nos sirve para listar directorios y archivos pero también nos listará los que están ocultos:

![whoami](/assets/images/Linux/comandos_basicos/ls-la.png)

> En linux los elementos ocultos inician con un punto, por ejemplo: .datos

---

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

---

## Manejo de rutas y TAB

Una vez entendimos un poco el funcionamiento del comando `cd` toca ir a explicar unas cuantas cosas más.

Digamos que estamos en la siguiente ruta:

![whoami](/assets/images/Linux/comandos_basicos/descargas.png)

Y deseamos viajar a la carpeta `Imágenes` pero queremos ir de una forma más rápida y no tener que escribir todo desde `/home/d4nsh/Imágenes` , entonces lo que podemos usar en este caso para resumir el directorio por defecto que es `/home/d4nsh` podemos usar esto: `~/`

Este símbolo ~ representa a la ruta por defecto del sistema que es la carpeta home de nuestro usuario, por ejemplo:

![whoami](/assets/images/Linux/comandos_basicos/home.zip.png)

Podemos ver que viajamos a Imágenes usando el comando cd y usamos el símbolo `~` que es lo mismo que `/home/d4nsh` y ahora nos facilita el trabajo de no tener que escribir toda la ruta de home de nuestro usuario.

---

### Auto-completado de rutas con TAB

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

## Migracion de shell

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

---

# Operadores logicos , control del flujo (stdout y stderr) y procesos en segundo plano

Ahora sigue ver sobre los operadores lógicos, saber que son y también control de flujo, y procesos en segundo plano.

## Concatenacion de comandos

Existe una forma de concatenar comandos para ejecutar 2 o más comandos en una sola linea (one liner), por ejemplo si queremos ejecutar el comando `whoami` y también el comando `ls` en una sola linea podemos concatenar ambos usando el punto y coma `;` como podemos ver:

![whoami](/assets/images/Linux/operadores/concatenados.png)

Podemos ver que nos dio el output de los 2 comandos.

> El output significa la salida de los comandos que hemos ejecutado que se muestran en pantalla.

Podemos ver que primero nos dio el output del comando whoami seguido del comando ls.

Si ponemos un comando que no existe concatenado con uno que si existe sucederá esto:

![whoami](/assets/images/Linux/operadores/error.png)

Podemos ver que el comando "whoa" no existe, pero aún así si ejecuto el ls ya que ese comando si existe, y vemos que en el output nos da un error en la salida del comando whoa, ya que no existe y nos dice que el comando no ha sido encontrado.

> Cuando recibes un error en pantalla como el del comando whoa se le denomina stderr, ya que significa que hubo un error, por el contrario si todo es exitoso se le denomina stdout a la salida de tu comando como en este caso lo es el ls.

----

## Ver codigos de estados de un comando o proceso

Cada que ejecutamos un comando, ya sea que haya sido exitoso o no, siempre por detrás se genera un código de estado ante el último comando ejecutado.

Los más comunes son los siguientes:

| Valor de estado | significado                                                                                       |
|-----------------|---------------------------------------------------------------------------------------------------|
| 0               | Indica que la ejecución del comando o proceso se ha realizado con éxito.                          |
| 127             | Este estado significa cuando el comando dado no existe en la ruta de la variable de entorno PATH. |
| 1               | Indica que el proceso tuvo un error y nos ha mostrado una alerta sobre ese error.                 |

Hagamos unas pruebas con cada uno de estos estados de respuesta.

Primero ejecutaremos un comando que sea exitoso, osea que lo que hayamos ejecutado se haya realizado con éxito y como debe ser, por ejemplo un simple `ls`:

![whoami](/assets/images/Linux/operadores/0.png)

Después de ejecutar el ls, podemos ver que ejecutamos `echo $?` esto nos sirve para imprimir el estado que tuvo la ejecución anterior, en este caso podemos ver un valor 0 por lo que se ha realizado con éxito.

Pero por otro lado si llamamos a un comando que no existe y mostramos el estado:

![whoami](/assets/images/Linux/operadores/127.png)

Podemos apreciar que nos ha respondido el valor 127 que como sabemos, indica que el comando no existe dentro de la variable de entorno PATH.

![whoami](/assets/images/Linux/operadores/1.png)

Podemos apreciar que intentamos leer el contenido de un archivo que no existe y su respuesta de estado fue 1, que como sabemos indica que ha habido un error con alerta.

----

## Operadores logicos

Existen varios tipos de operadores lógicos en linux, veamos cuales son:

| Operador lógico | significado                                                                                                                                                                                                                                                                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| &&              | Este operador "AND" significa que si ambas expresiones son verdaderas entonces nos devuelve un valor positivo (true), y si alguna de las 2 expresiones no se cumple entonces devolverá un estado de error (false).                                                                                                                                                |
| \|\|            | El operador "OR" significa que aunque una de las 2 expresiones sea falsa, mientras una sea verdadera este se ejecutará sin problemas, dando 2 opciones a elegir, en caso de que la primera no se cumpla, tomara la segunda, que en caso de cumplirse devolverá un estado de respuesta verdadero (true), y obviamente si ninguna es verdadera devolverá un false. |
| !               | Y este operador no se usará por ahora ya que se toca en otros temas pero significa que si al evaluar las operaciones osea las expresiones, si esto da falso, entonces esto responderá con un estado verdadero, esto es para asegurarse de que algo no se este cumpliendo por cualquier motivo necesario, pero esto se verá después.                                                                                                                                                                                                                                                                                                                                                                 |

Para entender mejor los primeros 2 operadores veamos ejemplos:

### ejemplo del operador AND

![whoami](/assets/images/Linux/operadores/y.png)

Podemos ver que en la primera ejecución pusimos `whoami && ls` y como ambas expresiones son verdaderas ya que existen en el PATH, entonces se ejecutará la acción, en este caso es la ejecución del comando.

Pero si vemos abajo si desde un inicio la primera expresión es falsa, ambas se tomaran como falsas y no ejecutarán su función.

### Ejemplo del operador OR

![whoami](/assets/images/Linux/operadores/o.png)

Podemos apreciar en la imagen que aunque la primera expresión no exista en el PATH la cual es en este caso "wh" , vemos que como la primera expresión no existe, entonces paso a la siguiente y la ejecuto aunque no existiera la primera expresión.

Y en la segunda ejecución vemos que siempre tomará la primera expresión pero en caso de no existir pasará a la segunda para comprobar si esa otra opción existe.

----

## Control de flujo stdout y stderr

### stderr

Al ejecutar un comando, o una instrucción que genere un error como por ejemplo, intentaremos leer un archivo que no existe:

![whoami](/assets/images/Linux/operadores/stderr.png)

Podemos ver que por debajo se manifiesta el mensaje de error que se le conoce como stderr ya que nos esta mostrando una salida con un mensaje erróneo.

Pero podemos ocultar esto en caso de que nos sea molesto y queramos omitir esta salida de error aunque el comando no haya sido exitoso por cualquier motivo.

Para esto usamos el control de flujo, el stderr se identifica en su control de flujo como el valor numérico 2.

Entonces podemos hacer lo siguiente:

![whoami](/assets/images/Linux/operadores/2.png)

Podemos apreciar que al ejecutar esto ya no nos mostró el aviso y en la segunda ejecución podemos ver que aunque fue un estado de error, ya no nos mostró ningún aviso de error en la pantalla, y esto fue porque redirigimos la salida del error hacía la ruta `/dev/null`.

La ruta `/dev/null` es una ruta del sistema donde todo lo que se meta dentro de esa ruta será eliminado permanentemente, es algo así como un agujero negro dentro del sistema.

Vemos que usamos `2>/dev/null` después de el comando, y esto se hace para como dijimos redirigir el stderr hacía esa ruta y sea desaparecida sin verla en pantalla en ningún momento a pesar de que no haya sido una ejecución exitosa.

El número 2 indica que la salida en caso de ser errónea, entonces será redirigida a el `/dev/null` pero usamos el símbolo de mayor que `>` para redirigir el estado de error osea el 2 a la ruta > /dev/null.

### stdout

De igual manera que el error, también podemos redirigir la salida de un comando exitoso.

![whoami](/assets/images/Linux/operadores/1.1.png)
> Es exitoso ya que el archivo que intentamos leer si existe, pero no queremos ver su salida.

Podemos apreciar que es lo mismo pero simplemente cambio el valor de 2 a 1 que el 1 significa stdout, salida exitosa.

---

### redirigir ambos flujos a la vez

Ahora si queremos ocultar el estado stdout, y el stderr a la vez, haremos lo siguiente:

![whoami](/assets/images/Linux/operadores/ambos.png)

Podemos apreciar que usando: `&>/dev/null` tanto de forma exitosa y no exitosa pudimos ocultar ambos casos.

Y lo que hacemos aquí es que simplemente redirigimos las 2 salidas a la ruta que ya sabemos /dev/null/ para desaparecer cosas.

---

### ¿Para que ocultar el flujo de algo?

Puede que te estés preguntando esto ya que por el momento no parece tener sentido, pero pongamos un ejemplo sencillo.

Al abrir un programa por ejemplo:

![whoami](/assets/images/Linux/operadores/telegram.png)

En este caso estamos abriendo telegram desde la terminal y vemos muchas advertencias pero nosotros no queremos ver esto, por lo que podemos redirigir esto para tener la terminal limpia:

![whoami](/assets/images/Linux/operadores/telegramlimpio.png)

Podemos apreciar que al redirigir el flujo ya no nos muestra nada y es más cómodo estar así , pero obviamente tiene muchas funciones mejores que estas, esto solo fue un simple ejemplo.

Por ejemplo algo más extenso sería al momento ya de programar scripts en bash y requieras la ejecución de ciertos programas, comandos, etc. Entonces será muy útil esto para no llenar la pantalla de quien ejecuta el script haciendo que tenga un mal aspecto.

---

## procesos en segundo plano

Como en el ejemplo anterior vimos que al abrir un programa o algún proceso por terminal esta se queda en espera, se quedará así a menos que cierres la terminal pero si la cierras se cerrara también el programa que haz abierto con ella.

Para solucionar esto podemos optar por poner el proceso en segundo plano.

![whoami](/assets/images/Linux/operadores/id.png)

Podemos ver que al final de la ejecución del programa pusimos un símbolo de &, y este símbolo al final de un proceso indica que lo que se va a ejecutar se haga en segundo plano, y podemos ver que nos lanza un numero que es un identificador llamado "pid" process id, el cuál se le asigno a el proceso que se abrirá en segundo plano.

Pero aún hecho esto si cerramos la terminal se cerrara el programa que abrimos con el ya que el programa aún depende de la terminal, pero para hacerlo independiente usaremos el comando `disown` para hacer independiente el proceso anterior:

![whoami](/assets/images/Linux/operadores/disown.png)

Y de esta forma podremos cerrar la terminal sin perder el programa abierto ya que ya no depende de la terminal.

> Esta no es la manera más recomendada de ejecutar programas en linux, ya que se puede facilitar simplemente ejecutándolos desde el menú de apps o desde un atajo de teclado si es que usas bspwm o algún parecido, pero explico esto ya que es muy importante para cuando profundicemos más.

<br>

---

# Descriptores de archivo

Para crear un descriptor de archivo podemos hacer lo siguiente:

![whoami](/assets/images/Linux/descriptores/5.png)

Lo que estamos haciendo aquí es que con el comando `exec` estamos creando un descriptor de archivo, este descriptor que estamos creando se identificara con el ID 5, y contendrá permisos para leer y escribir dentro de ese archivo, esto se lo indicamos usando los `<>` el símbolo de menor que significa que asignas el permiso de lectura, y el símbolo de mayor que, significa que asignas el permiso de escritura en el descriptor de archivo, y por último le damos un nombre al archivo en este caso será "archivo".

Una vez lo creamos hicimos un ls para apreciar que el archivo se ha creado y al hacerle cat nos dice que no contiene nada y es normal ya que no hemos metido ningún contenido.

---

## Redirigir un output dentro de un descriptor de archivo

Si queremos redirigir la salida de un comando hacía el descriptor de archivo que hemos creado podemos hacer lo siguiente:

![whoami](/assets/images/Linux/descriptores/redirigir.png)

Lo que estamos haciendo es redirigir la salida del comando whoami usando el símbolo `>` y con el & lo que hacemos es llamar a el id 5 que sabemos que es del archivo que creamos anteriormente, por lo que al ejecutar eso y leer el contenido del archivo vemos que ahora la salida del comando whoami se ha redirigido hacía el descriptor de archivo.

Y si ahora queremos meter otro output dentro del mismo descriptor de archivo podemos hacerlo:

![whoami](/assets/images/Linux/descriptores/pwd.png)

Podemos apreciar en la primera ejecución que se esta enviando el output del comando pwd hacía el descriptor de archivo con el id 5, en este caso es el que creamos antes.

Y al leer el archivo podemos apreciar que se agrego el contenido encima del anterior sin reemplazarlo, de esta forma se guardan multiples cosas sin ser reemplazadas.

---

## Finalizar de escribir en un descriptor de archivo

Si ya no queremos meter datos dentro de un descriptor de archivo podemos cerrarlo de la siguiente forma:

![whoami](/assets/images/Linux/descriptores/cerrar.png)

De esta forma ya no podremos meter datos dentro de este descriptor de archivo ya que lo hemos finalizado.

Y si intentamos meter datos nos saldrá esto:

![whoami](/assets/images/Linux/descriptores/error.png)

Podemos ver que ya nos sale un error ya que ya hemos cerrado el descriptor de archivo anteriormente.

---

## Hacer copias de un descriptor de archivo

![whoami](/assets/images/Linux/descriptores/datos.png)

Creamos un nuevo descriptor de archivo con el id 3, permisos de escritura y lectura, y que se llame "datos" en este caso.

Después le metemos algo, en este caso el output del comando whoami, y al mostrar su contenido vemos que se guardo con éxito.

Ahora para hacer una copia de este descriptor haremos lo siguiente:

![whoami](/assets/images/Linux/descriptores/copia.png)

Podemos ver que con exec asignamos un nuevo descriptor de archivo con el id 8, y con `>&3` indicamos que ese nuevo descriptor apuntará a el descriptor con id 3.

Y vemos que no se duplico el archivo, ya que lo que se duplica es el descriptor en si con el contenido más no el archivo.

Ahora si metemos datos dentro del nuevo descriptor:

![whoami](/assets/images/Linux/descriptores/duplicado.png)

Podemos apreciar que aunque metimos el output del comando pwd dentro del descriptor con el id 8, vemos que se refleja dentro de el archivo "datos" que pertenece al descriptor con el id 3.

Si cerramos el descriptor con el id 3:

![whoami](/assets/images/Linux/descriptores/fail.png)

Vemos que ya no nos deja obviamente ya que lo hemos cerrado, pero aún tenemos el duplicado y podremos hacerlo desde ese:

![whoami](/assets/images/Linux/descriptores/output.png)

Podemos ver que aquí si nos permitió meter el output al descriptor con el id 8, el cuál apunta hacía el archivo datos ya que al duplicarlo obtuvo esa referencia por lo que vemos que se ha pasado correctamente el output.

> No olvides cerrar el descriptor copia.

<br>

----

# Lectura e interpretacion de permisos + modos de escribir en archivos

Antes de ver la lectura e interpretación de permisos veremos algo básico pero necesario.

## Comando file y escritura en archivos

`file` : Este comando se usa para crear un archivo, por ejemplo:

![img](/assets/images/Linux/lectura_permisos/file.png)

Podemos ver que hemos creado un archivo llamado "archivo.txt" el cuál vemos que se creo correctamente al verificarlo con un ls.

Ahora hay multiples formas de editar el contenido de un archivo, por ejemplo si queremos meter un texto dentro del archivo podemos hacerlo así:

![img](/assets/images/Linux/lectura_permisos/contenido.png)

Podemos ver que estamos metiendo el output del comando echo con el contenido que queremos meter dentro del archivo, ya sabemos que con el símbolo de mayor que se redirige el output hacía un sitio, en este caso al archivo.

Y vemos que al hacerle un cat leemos su contenido.

Pero si intentamos meter más texto a ese mismo archivo de esta misma manera sucederá lo siguiente:

![img](/assets/images/Linux/lectura_permisos/otrotexto.png)

Podemos apreciar que el texto anterior se ha borrado y a cambio se ha sobrepuesto este texto nuevo.

Para evitar que un contenido se sobre-escriba encima del otro, haremos uso de dobles símbolos de mayor que:

![img](/assets/images/Linux/lectura_permisos/doble.png)

De esta forma el texto anterior ya no sera reemplazado.

---

## Uso de nano

Otra forma de editar archivos más fácil es usando el editor de texto `nano`:

![img](/assets/images/Linux/lectura_permisos/nano.png)

Al ejecutar este comando y al darle el archivo que queremos editar nos abrirá lo siguiente:

![img](/assets/images/Linux/lectura_permisos/nano-gui.png)

Desde aquí mismo ya podemos ir editando el texto.

Abajo vemos una serie de elementos que nos pueden ayudar, el símbolo de ^ significa ctrl, por ejemplo para salir se usa ctrl + x, o para buscar algo dentro del archivo se usa ctrl + f, para cortar una linea entera de texto se usa ctrl + k pero debes tener el cursor a partir de donde quieres cortar el contenido.

Para pegar contenido que tengas en el portapapeles, en nano se pega contenido con `ctrl + shift + v` y para copiar `ctrl + shift + c`.

Y por último para guardar el contenido se usa `ctrl + s`.

Ahora pasaremos a la parte de los permisos en el sistema.

---

## Lectura e interpretacion de permisos, mkdir

Con el comando `mkdir` nos sirve para crear un nuevo directorio, osea una carpeta:

![img](/assets/images/Linux/lectura_permisos/mkdir.png)
> La carpeta la hice para explicar los permisos.

Al hacer un `ls -l` veremos lo siguiente:

![img](/assets/images/Linux/lectura_permisos/permisos.png)

Si podemos ver bien, primero están los permisos que en breve profundizaremos en ellos.

Después nos muestra el propietario y grupo al que pertenece ese archivo o directorio, también vemos su peso, y hora de creación etc.

Pero lo que nos interesa es lo de los permisos:

![img](/assets/images/Linux/lectura_permisos/lectura.png)

En los permisos del directorio nos muestra "d" al inicio que indica que es un directorio.

Y en los permisos del archivo nos muestra un simple punto "." al inicio para saber que se trata de un archivo.

Vemos lo siguiente en los permisos del directorio:

rwx   r-x   r-x

> Estos valores siempre se separan en conjuntos de 3, la "d" no la tomamos en cuenta ya que solo indica que es un directorio.

| Permiso | significado                                                                                                                               |     |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| r       | permiso de lectura en el archivo o directorio.                                                                                       |
| w       | permiso de escritura en el archivo o directorio.                                                                                     |
| x       | permiso de ejecutar un archivo, programa, etc, pero en caso de que este permiso este en un directorio, indica que podemos entrar a dicho directorio. |

Si vemos en los permisos del directorio:

rwx   r-x   r-x

Podemos ver que los hemos separado en 3 conjuntos, ¿y esto porque?: Lo hacemos así ya que cada conjunto de estos permisos pertenecen a lugares diferentes.

El primer conjunto pertenece a los permisos que el usuario propietario de ese directorio tiene sobre ese directorio.

El segundo conjunto pertenece a los permisos que el grupo al que pertenece ese directorio tiene sobre el, por ejemplo si algún usuario dentro de la red de mi linux tiene asignado el grupo al que pertenece este archivo, entonces se le asignaran estos permisos del segundo conjunto.

Y por último el tercer conjunto pertenece a otros, por ejemplo alguien que no es dueño del archivo y no esta en el grupo del archivo, entonces se le asignan esos permisos del tercer conjunto.

Siempre van en orden rwx rwx rwx pero al desactivar un permiso se usa un guion.

Por eso vemos que el propietario tiene todos los permisos, los grupos solo pueden leer, y ejecutar pero no escribir.

Y con los otros es lo mismo que grupos.

---

### Un ejemplo mas para aclarar la lectura de permisos

Ahora veremos los permisos del archivo:

.rw- r-- r--

Sabemos que el punto indica que es un archivo y no un directorio que en su caso sería "d".

Ahora los separamos en conjuntos de 3:

rw-   r--   r--

Si entendimos bien, sabremos que el propietario tiene permiso de leer y escribir en el archivo pero no de ejecutarlo.

Los grupos y otros solo pueden leer el archivo pero no modificarlo ni ejecutarlo.

---

## Prueba de permisos 

Haremos otra prueba para entender un poco más, listamos con detalle el siguiente archivo:

![img](/assets/images/Linux/lectura_permisos/passwd.png)

Podemos ver que en este caso nosotros somos parte del grupo de otros ya que no somos el propietario, y tampoco estamos en el grupo root, podemos verlo con id:

![img](/assets/images/Linux/lectura_permisos/noroot.png)

Por lo que no estamos tampoco en el grupo, así que nuestros permisos son los de otros.

Sabemos que se separa de 3 conjuntos:

| propietario | grupo | otros |
| ----------- | ----- | ----- |
| rw-         | r--   | r--   |

Y pertenecemos al último conjunto que es el de otros, así que se nos asignas esos permisos hacía ese archivo.

Podemos leer el contenido:

![img](/assets/images/Linux/lectura_permisos/passwd-content.png)

Pero no podemos modificarlo:

![img](/assets/images/Linux/lectura_permisos/denegado.png)

Ya que no tenemos los permisos de escritura en este archivo.

<br>

---

# Asignacion de permisos

Ahora que ya sabemos leer los permisos, vamos a aprender a asignar esos permisos.

Cuando somos el propietario ya sea de un directorio, archivo, etc. Podemos modificar también el grupo al que pertenece ese archivo y también su propietario.

Veamos un ejemplo:

> Primero entre como el usuario root para crear un archivo y después con `su d4nsh` volví a ser el usuario d4nsh para hacer la prueba.

![img](/assets/images/Linux/escritura_permisos/root.png)

Ya como el usuario d4nsh, podemos ver que hay un archivo el cuál el propietario es root, y su grupo es root.

Como no somos el propietario, como podemos ver en la segunda ejecución vemos que somos d4nsh, así que nuestros permisos son los del último conjunto los cuales son solo de lectura.

Y podemos ver que no podemos escribir en el archivo ya que no tenemos permiso.

Así que volvemos a convertirnos en root con `sudo su` para poder modificar los permisos y ver como se hace:

![img](/assets/images/Linux/escritura_permisos/test.png)

Primero, podemos apreciar que usamos `whoami` para mostrar que nos convertimos en root.

Después mostramos los permisos del archivo, los cuales son: `rw-   r--   r--` y vemos que "otros" no tienen permiso de escritura pero se lo queremos agregar.

Así que usaremos el comando `chmod` esto sirve para modificar los permisos de algo.

En este caso como somos el propietario ya que root lo es, entonces podemos modificar los permisos de este archivo, así que queremos que los que pertenecen a "otros", tengan el permiso de escritura sobre ese archivo.

Por lo que haremos lo siguiente:

![img](/assets/images/Linux/escritura_permisos/asignacion.png)

Podemos ver que usamos: `chmod o+w archivo.txt` 

Lo que significa esto es que la o significa "otros", y el símbolo de + significa que asignaremos un permiso, la w es para asignar ese permiso, y pasamos el archivo al cual se le modificaran esos permisos, en este caso es archivo.txt.

Y podemos ver abajo que al hacer nuevamente un ls -l apreciamos que el permiso "w" de escritura ya esta asignado en "otros", y al volver a ser d4nsh y intentar meter contenido ya podremos ya que hemos asignado ese permiso:

![img](/assets/images/Linux/escritura_permisos/w.png)

Vemos que hacemos un exit para volver a ser d4nsh, después mostramos el permiso que vimos que se asigno anteriormente y probamos meter contenido que antes no pudimos y ahora si ya que tenemos el permiso en "otros".

Y podemos ver que el contenido se agrego correctamente gracias a la asignación del permiso de escritura en "otros".

Ahora si queremos remover un permiso se usa el signo de menos `-` en lugar del de `+` y de esta forma asignamos y removemos permisos.

Y si quieres cambiar permisos del propietario se usa `u` que significa user.

Si quieres cambiar el permiso de grupos se usa `g` que significa group.

Recordemos estos valores:

| Letra | significado  |
| ----- | ------------ |
| u     | propietario. |
| g     | grupo.       |
| o     | otros        |

Y los símbolos:

`+` para asignar un permiso.
`-` para remover un permiso.

---

## Cambiar diferentes permisos en una sola linea

Ahora si queremos cambiar diferentes permisos en una sola ejecución, veamos como se hace.

Supongamos que queremos cambiar:

![img](/assets/images/Linux/escritura_permisos/permisos.png)

estos permisos, por otros.

rw-   r--   rw-

Queremos cambiarlos por:

rwx   rwx   r--

Por ejemplo.

Así que haremos lo siguiente:

![img](/assets/images/Linux/escritura_permisos/varios.png)

Apreciamos que separamos con una coma al momento de asignar los de cada conjunto.

Y podemos adjuntar varios en uno solo como fue en el g+wx esto para asignar los 2 permisos de ese conjunto, por lógica también podemos hacer esto al remover permisos.

---

## Cambiar grupo de un archivo/directorio

Para hacer esto usaremos el comando `chgrp` que significa change group, cambiar grupo, y le pasamos el grupo al que queremos que se cambie el archivo dado:

![img](/assets/images/Linux/escritura_permisos/cambio.png)

Podemos apreciar que el grupo de el archivo.txt ha cambiado del grupo d4nsh a el grupo video, como vemos en la imagen.

De esta forma se cambia el grupo a algo.

---

## Cambiar propietario de un archivo/directorio

Y ahora para cambiar el propietario usamos el comando `chown` de change owner, cambiar propietario, y le pasamos el propietario que queremos que se cambie el archivo o directorio dado:

![img](/assets/images/Linux/escritura_permisos/root1.png)

Podemos apreciar que esta vez usamos los permisos de `sudo` ya que como es root necesitamos su permiso para asignarle un archivo como propietario.

Y abajo podemos aperciar que el usuario propietario del archivo ya es root y no d4nsh.

De esta forma podemos cambiar el propietario de algo.

---

## Asignar propietario y grupo en un solo comando

Veamos:

![img](/assets/images/Linux/escritura_permisos/default.png)

Podemos apreciar que usamos el comando que se usa para cambiar el propietario `chown` pero esta vez hicimos:

`sudo chown d4nsh:d4nsh archivo.txt`

Vemos que ponemos en el primer apartado d4nsh, que indica el propietario al que se cambiara el archivo, pero si también ponemos separado de dos puntos : el grupo, entonces esto automaticamente lodetectará que el segundo valor es para asignar el grupo y primero el propietario , para no usar 2 comandos diferentes, por lo que al hacer eso podemos ver debajo que el propietario y el grupo han sido cambiados a d4nsh.

Y fue gracias a el comando chown que pudimos hacer esto, recuerda:

![img](/assets/images/Linux/escritura_permisos/oneline.png)

Vemos que podemos hacerlo en un solo comando, también podemos usar el comando `chgrp` del mismo modo y esto funcionará igual pero obviamente en lugar de que primero sea el usuario el que se asigne, será el grupo ya que es su comando.

Y vemos que usamos sudo ya que como le quitaremos el propietario a root necesitamos su permiso ya que es el propietario y necesitamos su confirmacion.

<br>

---

# Crear un nuevo usuario

Ahora aprenderemos a crear un usuario nuevo, primero necesitamos ser root para hacer modificaciones en el sistema.

![img](/assets/images/Linux/crear_usuario/f4r.png)

Podemos ver que siendo como root, creamos el directorio f4r dentro de la ruta `/home/` Y esto es porque este directorio home será la carpeta por defecto de un nuevo usuario que vamos a crear:

![img](/assets/images/Linux/crear_usuario/useradd.png)

Lo que hicimos en este comando primero fue usar el comando `useradd` seguido de sus parametros , el primero es el nombre del nuevo usuario, en este caso es "f4r", después con -s indicamos que tipo de shell va a tener ese usuario, le indicamos que tendrá una bash `/bin/bash` y por último con el parametro -d le indicamos cúal va a ser su directorio personal, en este caso es el que creamos anteriormente `/home/f4r`.

Y podemos confirmar que se creo el usuario leyendo el archivo `/etc/passwd`:

![img](/assets/images/Linux/crear_usuario/passwd.png)

Vemos que se ha creado el usuario f4r y vemos que tiene su directorio personal al igual que la shell bash asignada.

<br>

Ahora le asignaremos una contraseña a este nuevo usuario, para ello usamos el comando `passwd` y le pasamos como parametro el usuario a modificar la contraseña:

![img](/assets/images/Linux/crear_usuario/passwdf4r.png)

Podemos ver que hemos asignado la contraseña al usuario f4r correctamente.

<br>

Ahora vemos que al hacer un ls -l podemos apreciar que el directorio de f4r le pertenece a root y también al grupo root:

![img](/assets/images/Linux/crear_usuario/root.png)

Pero queremos que le pertenezca al usuario f4r, por lo que lo vamos a modificar:

![img](/assets/images/Linux/crear_usuario/chown.png)

Podemos apreciar que hemos modificado correctamente el propietario y grupo del directorio f4r.

> No usamos sudo antes de ejecutar el comando ya que ya estamos como el usuario root y no es necesario.

---

## Migrar a otro usuario

Ahora migraremos a el nuevo usuario f4r, usaremos `su f4r` y entraremos automaticamente:

![img](/assets/images/Linux/crear_usuario/bash.png)

Podemos ver que al hacer simplemente este comando entramos como el usuario f4r, y no nos pidio la contraseña de f4r ya que como estabamos como root y tenemos los maximos privilegios sobre el sistema entonces tenemos admitido entrar a cualquier usuario sin proporcionar su contraseña.

Pero si estuviesemos como d4nsh, si nos pediria la contraseña al intentar migrar:

![img](/assets/images/Linux/crear_usuario/contra.png)

Podemos apreciar que aquí si nos pidió la contraseña del usuario f4r, ya que d4nsh no tiene permisos de acceder a cualquier usuario como root.

<br>

Podemos ver que estamos en la ruta `/home` en un inicio, pero vemos que si usamos el comando `cd` este nos llevará a nuestro directorio personal como podemos comprobarlo con `pwd`:

![img](/assets/images/Linux/crear_usuario/cd.png)

Esto fue gracias a que asignamos esta ruta como su directorio personal.

<br>

---

# Crear nuevo grupo

Ahora aprenderemos a crear nuevos grupos, en este ejemplo crearemos el grupo "Testing":

![img](/assets/images/Linux/crear_usuario/idgrupo.png)

> Recuerda estar como root al crear usuarios,grupos,modificar contraseñas, y cualquier actividad que requiera modificaciones en el sistema que cualquier usuario no privilegiado no pueda hacer.

Podemos apreciar que hemos creado el grupo correctamente usando el comando `groupadd` y pasandole como parametro el grupo a crear.

Después comprobamos que se ha creado este grupo "Testing" al comprobarlo en el archivo `/etc/group`, y podemos ver que se le asigno un gid(group id) con el valor de 1005 y también vemos que no aparece ningún usuario ya que nadie esta en este grupo por ahora.

## Asignar usuarios a grupos

Ahora para asigar usuarios a un grupo, en este caso asignaremos al usuario f4r al grupo "Testing":

![img](/assets/images/Linux/crear_usuario/usermod.png)

para ello usamos el comando `usermod` con el parametro -a que significa añadir algo a un usuario, y lo que le añadimos es al grupo que se pasa en el parametro -G en este caso es Testing, y por último le pasamos el usuario al que se le aplicarán estos cambios.

Y si vemos abajo en el cat podemos apreciar que ahora ya hay un usuario dentro del grupo "Testing" que podemos leer en el archivo `/etc/group/`.

Ahora migraremos a el usuario f4r y podremos ver que al hacer `id` se encuentra el grupo que asignamos anteriormente:

![img](/assets/images/Linux/crear_usuario/id.png)

Vemos que aparece el grupo Testing al cual pertenece el usuario f4r.

<br>

## Ejemplo extra de permisos

Veremos un último ejemplo sobre estos temas para repasar, crearemos una carpeta la cuál solo los que pertenecen al grupo Testing, puedan atravesar un directorio y escribir dentro de el.

Primero creamos el directorio:

![img](/assets/images/Linux/crear_usuario/dir.png)

Podemos ver que hemos creado un directiro llamado Archivos, y como somos root, el propietario y grupo de este directorio es root como podemos ver.

Ahora con el comando `chgrp` hemos cambiado el grupo de ese directorio a el grupo Testing:

![img](/assets/images/Linux/crear_usuario/change.png)

Podemos ver que ya pertenece este directorio a el grupo Testing.

<br>

Ahora solamente queda modificar los permisos como queremos, que otros no puedan atravesar el directorio ni leer nada dentro, y que solo el propietario y el grupo puedan escribir, leer y atravesar ese directorio:

![img](/assets/images/Linux/crear_usuario/final.png)

Y podemos apreciar que hemos asignado los permisos usando chmod como lo explicamos pero esta vez aplicado a lo requerido que en este caso es que solo el propietario y el grupo tengan control sobre el directorio pero no "otros".

Como el usuario d4nsh no esta dentro del grupo Testing, no podra ingresar al directiro ni hacer nada sobre el:

![img](/assets/images/Linux/crear_usuario/denegado.png)

Esto es ya que el usuario d4nsh no es el propietario ni pertenece al grupo, por lo que sus permisos son los de "otros", pero como lo configuramos sin ningun permiso entonces no podra hacer nada el usuario d4nsh sobre ese directorio.

<br>

Y por otro lado con el usuario f4r si que podremos atravesar el directorio, escribir y leer:

![img](/assets/images/Linux/crear_usuario/privilegios.png)

Podemos apreciar que como el usuario f4r pertenece al grupo Testing, tenemos los permisos de grupo.

<br>

---

# Notacion octal de permisos

Ahora veremos otra manera de asignar permisos, esto se hace de la siguiente forma, por ejemplo tenemos este archivo:

![img](/assets/images/Linux/permisos_octal/archivo.png)

Sus permisos son los siguientes:

`rw-   r--   r--`

Ahora después de separarlos en 3 conjuntos, en una hoja o donde quieras , debes agregar los siguientes valores por debajo:

```
rw-ㅤㅤr--ㅤㅤr--
|||ㅤㅤ|||ㅤㅤ|||
110ㅤㅤ100ㅤㅤ100
```

Si hay un permiso, agregamos un "1", y si no hay un permiso agregamos un "0".

Después vamos a agregar unas posiciones imaginarias:

```
rw-ㅤㅤr--ㅤㅤr--
|||ㅤㅤ|||ㅤㅤ|||
110ㅤㅤ100ㅤㅤ100
|||ㅤㅤ|||ㅤㅤ|||
210ㅤㅤ210ㅤㅤ210
```

Agregamos las posiciones en orden en cada conjunto en relación a los valores de arriba, estas pociciones inician desde 0 contando hasta 2. o sea 012, pero al revés.

Ahora se elevará el numero 2 a el exonente de la posicion, pero esto solo si en esa posicion hay un permiso.

Por ejemplo:

Empezaremos con el primer conjunto para no confundirnos:

```
rw-
|||
110   <--- binarios.
|||
210   <--- posiciónes.
```

En la posición 0 no hay permiso en su binario de arriba ya que hay un 0 arriba, por lo que se ignora ya que indica que no hay un permiso ahí.

En la posición 1 si hay permiso ya que hay un 1 en su binario de arriba, lo que indica que hay un permiso, por lo que elevamos 2 a el valor de esa posición, en este caso: 2¹ que nos da: 2

Y en la posición 2 también hay un permiso, por lo que elevaremos 2 a el valor de esa posición: 2² que nos da: 4

Luego sumamos estos valores: 2 + 4 = 6.

<br>

Y haremos esto mismo con los otros 2 conjuntos restantes:

```
r--
|||
100    <--- Ponemos los valores en binario, recuerda, 1 se pone si encima hay un permiso, y 0 si no hay.
|||
210    <--- Agregamos las posiciones 0,1,2 pero al revés.
```

Ahora sigue elevar el 2 dependiendo las posiciones y que exista un permiso, en la posición 0 no hay permiso arriba en el binario, por lo que se queda vacio.

En la posición 1 tampoco hay permiso por lo que se queda vacío.

Y en la posición 2 si hay permiso, por lo que elevamos el 2 a el valor de la posición: 2² que es igual a: 4.

Y como solo había 1 permiso en este conjunto entonces ya no hay con que sumarlo y se pasa así.

<br>

El tercer conjunto es lo mismo que el anterior por lo que igual es igual a 4.

Y una vez terminado nos quedarán así los permisos ya elevados:

```
rw-   r--   r--
6     4     4
```

Ahora tenemos el valor 644, este valor equivale a los permisos que vimos en un inicio dentro del archivo.

![img](/assets/images/Linux/permisos_octal/test.png)

Podemos ver que aplicamos este valor usando el comando chmod, y pasandole el archivo, y al comprobar nuevamente los permisos con ls -l, vemos que no se modifico nada ya que sus permisos son los que asignamos que ya tenian.

## Otro ejemplo para aclarar

Ahora supongamos que a ese mismo archivo anterior, queremos cambiarle los permisos a estos:

`rwx   r-x   r--   <--- permisos.`

Empezamos haciendo el binario dependiendo de si hay un permiso o no:

```
111   110   100   <--- binario.

Ahora agregamos las posiciones:

111   110   100   <--- Binario.

210   210   210   <--- Posiciones.
```

Ahora elevaremos el 2, a la potencia que nos indica la posición, recuerda que solo se aplica esto en caso de que haya un permiso en esa posición.

Primer conjunto:

```
rwx   <--- permisos.
|||
111   <--- binario.
|||
210   <--- posición.
```

En la posición 0 hay un permiso, por lo que elevaremos 2 a la potencia de esa posición: 2⁰ que es igual a 1.

En la posición 1 hay un permiso, por lo que elevaremos 2 a la potencia de esa posición: 2¹ que es igual a 2.

Por último la posición 2 tiene un permiso, por lo que elevamos el 2 a la potencia de esa posición: 2² que es igual a 4.

Sumamos estos valores y tenemos: 7

<br>

Ya sacamos el primer valor numerico del primer conjunto, ahora sacaremos los de los otros 2 conjuntos restantes:

segundo conjunto:

```
r-x   <--- permisos.
|||
101   <--- binario.
|||
210   <--- posición.
```

2 se eleva a la posición 0, ya que hay permiso en la posición: 2⁰ = 1.

En la posición 1 no hacemos nada ya que no hay permiso en la posición.

2 se eleva a la posición 2, ya que hay permiso en la posición: 2² = 4.

Al sumar esto da 5.

Hemos sacado el valor del segundo conjunto.

<br>

Por último sacaremos el tercer conjunto:

```
r--   <--- permisos.
|||
100   <--- binario.
|||
210   <--- posición.
```

Posición 0 y 1 se omiten ya que no hay permisos en sus posiciones.

La posición 2 tiene permiso, por lo que elevamos el 2 a esa posición: 2² = 4.

Y como no hay nada más con que sumarlo de este conjunto entonces ya tenemos el valor de este conjunto: 4.

Ahora ya sacamos el valor del tercer conjunto.

<br>

Y ya tenemos los valores de los 3 conjuntos, ahora simplemente los juntamos: 754

Y al asignar este valor a el archivo veremos que se asignaron los permisos deseados:

`rwx   r-x   r--   <--- permisos deseados.`

Resultado:

![img](/assets/images/Linux/permisos_octal/permisos.png)

Y podemos apreciar que se aplicaron correctamente como lo deseamos.

> Esto puede resultar muy tardado para algo simple pero con el tiempo, sobre todo si practicas vas a lograr hacerlo mucho más rapido y se te quedarán ciertos valores grabados.

<br>

## Alternativa por si la anterior te parece complicada

Aquí veremos otra manera de hacer esto un poco más rapido.

