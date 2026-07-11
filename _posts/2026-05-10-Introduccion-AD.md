---
layout: single
title: Introducción a Active Directory
excerpt: En proceso...
date: 2026-05-10
classes: wide
header:
  teaser: /assets/images/AD/AD.jpg
  teaser_home_page: true
categories:
  - test
tags:
  - test
---

<br>

## ¿Qué es el Active Directory?

Es una red de servicios centrada en una red windows, sirve para administrar una organización pequeña o demasiado grande, ya que a través de esta red, podremos gestionar los equipos, los usuarios, grupos, dispositivos en la red, archivos compartidos, servidores, etc.

**Active Directory Domain Server** Se encarga principalmente de autenticar inicios de sesión, permisos, básicamente los accesos a los que los usuarios tienen sobre esa información almacenada.

Pero estos entornos pueden estar mal configurados en cuanto a permisos y permitir a usuarios hacer ciertas cosas, como enumeración de recursos para una posible intrusión.

**Enumeración**: Un usuario dentro del entorno AD (active directory), que aunque no tenga privilegios altos, tiene la capacidad de poder enumerar cierta información que puede servir a los atacantes a entrar dentro de la organización a un nivel más profundo.

Algunas de las cosas que un usuario dentro del AD podría enumerar son las siguientes:

- **Domain Computers**: Son las computadoras dentro del dominio AD.
- **Domain Users**: Los usuarios que usan dichos equipos.
- **Organizational Units (OUs)**: Son contenedores que permiten organizar usuarios y computadoras para aplicar políticas especificas:
- **Default Domain Policy**: La configuración general que se aplica a todos los usuarios y computadoras por defecto.
- **Password Policy**: Se encarga de definir la política de las contraseñas, como complejidad, longitud, etc.
- **Group Policy Objects (GPOs)**: Es la función principal para realizar configuraciones de software y seguridad de forma masiva en toda la red.
- **Access Control Lists (ACLs)**: Definen quien tiene permiso para leer, escribir en un objeto dentro de la red AD.
- **Functional Domain Levels**: Esta determina las capacidades técnicas disponibles en base a la versión en uso de windows server.
- **Domain Group Information**: Para detalles sobre los grupos disponibles, se usa para administrar permisos de forma masiva.
- **Domain Trusts**: Permiten el acceso de un dominio de confianza a otro para que así un usuario pueda acceder a recursos de otros dominios.

## Estructura básica de Active Directory

```
ECORP.LOCAL/
├── ADMIN.ECORP.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.ECORP.LOCAL
└── DEV.ECORP.LOCAL
```

El dominio **ECORP.LOCAL** en este caso es el dominio raíz, el cuál contiene los siguientes subdominios: **ADMIN.ECORP.LOCAL, CORP.ECORP.LOCAL y DEV.ECORP.LOCAL**, estos dominios están dentro del mismo entorno AD.

Cada dominio puede contener rutas, políticas, reglas, grupos, usuarios, etc. El AD es una gran base de datos.

En este caso vemos que en el subdominio **ADMIN.ECORP.LOCAL** tenemos **GPOs** (Group Policy Objects) que recordamos que se encargan de realizar configuraciones de software y seguridad en toda la red, veamoslo como "Manual de reglas". y también tenemos **OU** que nos permite organizar usuarios y computadoras para aplicar las politicas necesarias son contenedores, en este caso vemos que esto en consecuencia de arriba hacía abajo, obviamente va tomar en cuenta a **COMPUTERS** y **USERS**, ya que la raíz de estos dos es **EMPLOYEES**, todo lo que este dentro de ambos objetos y sus contenidos, serán evaluados si pertenecen a el grupo **HQ Staff** esto es como un filtro, y en caso de pertenecer, se aplicarán las GPOs correspondientes, en caso de no pertenecer a **HQ Staff** simplemente la maquina lo ignora.

> Quizá ahora no notes sentido en llamar por separado a computers y users si solo contienen un valor cada uno, pero espera a que los empleados sean miles y verás la eficiencia.

A esta estructura se le conoce como Forest (bosque).

---

## Confianza de dominios

En el siguiente gráfico podemos ver dos dominios, A y B:

![image](/assets/images/AD/images/domains.png)

El dominio A: pertenece a el dominio **logistics.local**.
El dominio B: pertenece a el dominio **wire.local**.

En este caso hay una relación de confianza, y el Dominio A, puede acceder a los recursos del dominio B incluyendo a sus subdominios, por ejemplo, **logistics.local** puede hacer una consulta a **dev.wire.local**, y **dev.wire.local** puede acceder a la raíz del dominio A, pero no puede acceder a los subdominios del dominio A.

> Es posible una conexión entre subdominios A y B pero es necesario una configuración especifica para esto.

---


## Terminologías de Active Directory

Esta lista es un recordatorio de las terminologías usadas, en caso de querer saber alguna simplemente vuelves a esta página.

**Object**: Un objeto puede ser definido como cualquier recurso dentro del directorio activo, OUs, impresoras, usuarios, computadoras, domain controllers, etc.

**Attributes**: Cada objeto en AD, tiene sus atributos, por ejemplo, una computadora contiene hostname y el DNS name. Todos los atributos tienen un nombre LDAP asociado para llamar a su funcionalidad, por ejemplo **DisplayName** te devuelve el nombre completo de un usuario.

**Schema**: Define el tipo de objetos y sus atributos asociados que pueden existir en un AD, por ejemplo, los users pertenecen a la clase user, cuando un objeto se crea a partir de una clase, se le llama **instantiation** y cuando este objeto se crea a partir de una clase especifica se le llama **instance**; el objeto computadora es una instancia de la clase **computer**.

**Domain**: Los dominios son una red formada por objetos: computadoras, usuarios, OUs, grupos, etc. Pueden operar de manera independiente o conectadas.

**Forest**: Es el conjunto de uno o más dominions dentro del AD, esto es la vista en general, viendo el "bosque" completo, esto contiene todo lo de AD, dominios, usuarios, grupos, OUs, GPOs, etc. un bosque puede contener uno o más dominios, pueden trabajar independientemente o unidos entre si dependiendo.

**Tree**: Losa arboles son básicamente los elementos que componen el bosque, en este caso son subdominios (como en la imagen de arriba), por ejemplo **ecorp.local** puede tener subdominios, por ejemplo **dev.ecorp.local** y estos están dentro de la misma red (forest).

**Container**: Los contenedores son objetos que contienen otros objetos, por ejemplo un contenedor puede contener GPOs para ser aplicadas a las computadoras.

**Leaf**: Estos objetos no contienen otros objetos, están al final de la estructura del árbol (tree).

**GUID**: Global Unique Identifier es un ID único que se asigna al momento de crear un dominio, usuario o grupo, este ID es único e irrepetible y es con el que se identifica cada objeto dentro del AD, este valor se almacena en el atributo `ObjectGUID` del objeto especifico.

**Security principals**: Son cualquier cosa que el sistema pueda autenticar, es decir, usuarios, grupos, computadoras, cuentas, procesos en segundo o primer plano, etc. Estos se encargan de administrar el acceso a otros recursos dentro del entorno AD. pero cuando estás solamente en un equipo local (iniciar sesión en el equipo físico) esto no se maneja por el AD, sino por **SAM**: Security Accounts Manager que reside localmente dentro de cada maquina física.

**SID**: Security Identifier, 
