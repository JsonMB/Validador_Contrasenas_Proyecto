# Validador de contraseñas – Proyecto final

**Materia:** Lógica de Programación II  
**Autores:** Jeison Moreno Bertel y Luis Felipe Uribe Mesa

## 1. Archivos

- `Validador_Contrasenas_GUI_POO.py`: aplicación principal.
- `requirements.txt`: dependencias externas necesarias para el cifrado y el monitoreo de recursos.

## 2. Requisitos e instalación

Se recomienda Python 3.10 o superior. En Windows, Tkinter normalmente viene incluido con la instalación oficial de Python.

Abre CMD o la terminal de Visual Studio Code en la carpeta donde guardaste el proyecto y ejecuta:

```bash
pip install -r requirements.txt
```

También puedes instalar los paquetes directamente:

```bash
pip install cryptography psutil
```

## 3. Cómo ejecutar

En la misma terminal, ejecuta:

```bash
python Validador_Contrasenas_GUI_POO.py
```

También puedes abrir el archivo desde Visual Studio Code y ejecutarlo con Python.

## 4. Secciones de la aplicación

### Validador

1. Escribe una contraseña.
2. Pulsa **Validar contraseña**.
3. El menú superior permite cambiar entre las secciones. La aplicación comprueba cinco condiciones: mínimo 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.
4. Muestra el nivel alcanzado, el porcentaje de condiciones cumplidas y las recomendaciones.

### Hash

1. Escribe una contraseña y pulsa **Generar hash**.
2. La aplicación crea un hash PBKDF2-HMAC-SHA256 con una sal aleatoria.
3. Cambia el contenido del campo por una contraseña candidata y pulsa **Verificar contraseña**.
4. El programa compara el resultado sin recuperar el texto original. Para la demostración se conservan hasta tres intentos.

El hash se conserva solamente en la memoria de la aplicación. Esta versión no utiliza una base de datos ni guarda el hash en un archivo.

### Cifrado AES

1. Escribe una contraseña o un texto de prueba para cifrarlo de forma reversible.
2. Escribe una contraseña maestra de al menos 8 caracteres.
3. Pulsa **Cifrar texto** para generar un token AES-GCM.
4. Pulsa **Descifrar contenido** usando la misma contraseña maestra.
5. También puedes cambiar la contraseña maestra para comprobar que no se puede descifrar con una clave incorrecta.

El cifrado es una demostración reversible separada de la validación y del hash. Utiliza AES-GCM y deriva la clave con Scrypt.

### Rendimiento

- **CPU:** porcentaje de uso del proceso de la aplicación.
- **RAM:** memoria residente (RSS) utilizada por el proceso, expresada en MB.
- **Tiempo por operación:** duración medida para las validaciones, generación/verificación de hash y cifrado/descifrado.

Las mediciones se actualizan mientras la aplicación está abierta. Para comparar resultados, hagan varias pruebas con diferentes contraseñas y registren las condiciones de cada prueba. Los valores dependen del computador y de los programas que estén ejecutándose.

## 5. Dónde se aplica POO

- **Abstracción:** `ReglaValidacion` define el método que deben implementar las reglas concretas.
- **Herencia:** `ReglaLongitud`, `ReglaMayuscula`, `ReglaMinuscula`, `ReglaNumero` y `ReglaCaracterEspecial` heredan de `ReglaValidacion`.
- **Polimorfismo:** `ValidadorContrasenas` ejecuta `validar()` sobre cada regla sin necesitar conocer su clase concreta.
- **Encapsulamiento:** `ValidadorContrasenas` mantiene su lista interna de reglas como `_reglas` y permite consultarla mediante una propiedad.
- **Separación de responsabilidades:** `ServicioSeguridad` concentra las funciones criptográficas, `MonitorRecursos` obtiene las métricas y `AplicacionValidador` administra la interfaz.

## 6. Complejidad algorítmica para explicar en el póster

- **Validación:** O(n) en tiempo, donde n es la longitud de la contraseña. Se recorren los caracteres para comprobar un conjunto fijo de cinco reglas. El espacio auxiliar del proceso de comprobación es O(1), sin contar los pequeños resultados que se muestran en pantalla.
- **PBKDF2:** su costo depende principalmente del número configurado de iteraciones (600.000). Se utiliza deliberadamente un cálculo más costoso que una comparación simple para dificultar los intentos masivos de adivinación.
- **AES-GCM:** el cifrado y descifrado del contenido crecen aproximadamente de forma lineal con el tamaño del texto. La derivación de la clave con Scrypt agrega un costo fijo configurado para cada operación.

No presenten tiempos, porcentajes de CPU o memoria como resultados universales: deben tomar los valores que obtengan al ejecutar el programa en su propio computador.

## 7. Aclaraciones importantes de seguridad

- **Hash no es cifrado:** el hash está diseñado para no poder revertirse. En esta aplicación se usa PBKDF2-HMAC-SHA256, una sal aleatoria y comparación en tiempo constante.
- **Cifrado sí es reversible:** AES-GCM permite recuperar el texto original con la contraseña maestra correcta y también detecta modificaciones del contenido cifrado.
- Para un sistema real de inicio de sesión, las contraseñas normalmente se verifican mediante un hash especializado; no se almacenan en texto plano ni se cifran para recuperarlas después.
- Esta aplicación es un prototipo académico. No tiene base de datos, registro de usuarios ni almacenamiento persistente de credenciales.
