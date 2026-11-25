"""
Materia: Logica de Programacion II
Proyecto: Reto #6 - Validador de Contrasenas
Autores: Jeison Moreno Bertel y Luis Felipe Uribe Mesa

Version ampliada con:
- Interfaz grafica Tkinter.
- Programacion Orientada a Objetos (abstraccion, herencia, encapsulamiento y polimorfismo).
- Validacion de requisitos de seguridad.
- Hash de contrasenas con PBKDF2-HMAC-SHA256.
- Cifrado reversible de demostracion con AES-GCM y derivacion de clave Scrypt.
- Medicion y graficas de tiempos de ejecucion, CPU y memoria RAM.

Dependencias externas:
    pip install cryptography psutil

Nota de seguridad:
El hash es el mecanismo apropiado para almacenar contrasenas de autenticacion.
El cifrado AES-GCM se incluye como demostracion de cifrado reversible para el proyecto;
no se recomienda guardar contrasenas de inicio de sesion cifradas cuando basta con
verificarlas mediante un hash seguro.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string
import time
import tkinter as tk
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from tkinter import messagebox, ttk
from typing import Callable, Deque, List, Optional, Sequence, Tuple

try:
    import psutil
except ImportError:  # La aplicacion puede abrir, pero no mostrara metricas reales de CPU/RAM.
    psutil = None

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # La validacion y el hash siguen disponibles sin cryptography.
    AESGCM = None

    class InvalidTag(Exception):
        """Excepcion de reserva cuando cryptography no esta instalado."""


# -----------------------------------------------------------------------------
# 1. MODELO DE VALIDACION: abstraccion, herencia y polimorfismo
# -----------------------------------------------------------------------------


class ReglaValidacion(ABC):
    """Clase abstracta que define el contrato de todas las reglas."""

    nombre: str
    descripcion: str

    @abstractmethod
    def validar(self, contrasena: str) -> bool:
        """Devuelve True si la contrasena cumple esta regla."""
        raise NotImplementedError


class ReglaLongitud(ReglaValidacion):
    def __init__(self, longitud_minima: int = 8) -> None:
        self.longitud_minima = longitud_minima
        self.nombre = "Longitud minima"
        self.descripcion = f"Al menos {longitud_minima} caracteres"

    def validar(self, contrasena: str) -> bool:
        return len(contrasena) >= self.longitud_minima


class ReglaMayuscula(ReglaValidacion):
    def __init__(self) -> None:
        self.nombre = "Letra mayuscula"
        self.descripcion = "Contiene al menos una letra A-Z"

    def validar(self, contrasena: str) -> bool:
        return any(caracter.isupper() for caracter in contrasena)


class ReglaMinuscula(ReglaValidacion):
    def __init__(self) -> None:
        self.nombre = "Letra minuscula"
        self.descripcion = "Contiene al menos una letra a-z"

    def validar(self, contrasena: str) -> bool:
        return any(caracter.islower() for caracter in contrasena)


class ReglaNumero(ReglaValidacion):
    def __init__(self) -> None:
        self.nombre = "Numero"
        self.descripcion = "Contiene al menos un digito"

    def validar(self, contrasena: str) -> bool:
        return any(caracter.isdigit() for caracter in contrasena)


class ReglaCaracterEspecial(ReglaValidacion):
    def __init__(self) -> None:
        self.nombre = "Caracter especial"
        self.descripcion = "Contiene un simbolo (por ejemplo: !, @, #, $)"

    def validar(self, contrasena: str) -> bool:
        return any(caracter in string.punctuation for caracter in contrasena)


@dataclass
class ResultadoValidacion:
    resultados: List[Tuple[str, str, bool]]
    cumple_todo: bool
    porcentaje: int
    nivel: str
    recomendaciones: List[str]


class ValidadorContrasenas:
    """Administra reglas intercambiables y las evalua de forma polimorfica."""

    def __init__(self, reglas: Optional[Sequence[ReglaValidacion]] = None) -> None:
        self._reglas: List[ReglaValidacion] = list(reglas or [])

    def agregar_regla(self, regla: ReglaValidacion) -> None:
        self._reglas.append(regla)

    @property
    def reglas(self) -> Sequence[ReglaValidacion]:
        return tuple(self._reglas)

    def evaluar(self, contrasena: str) -> ResultadoValidacion:
        resultados: List[Tuple[str, str, bool]] = []
        recomendaciones: List[str] = []

        # Polimorfismo: se llama al mismo metodo validar() en cada tipo de regla.
        for regla in self._reglas:
            cumple = regla.validar(contrasena)
            resultados.append((regla.nombre, regla.descripcion, cumple))
            if not cumple:
                recomendaciones.append(regla.descripcion)

        total = len(self._reglas)
        aprobadas = sum(1 for _, _, cumple in resultados if cumple)
        porcentaje = round((aprobadas / total) * 100) if total else 0
        cumple_todo = bool(total) and aprobadas == total

        if porcentaje == 100 and len(contrasena) >= 12:
            nivel = "Muy fuerte"
        elif porcentaje == 100:
            nivel = "Fuerte"
        elif porcentaje >= 60:
            nivel = "Media"
        elif porcentaje >= 40:
            nivel = "Debil"
        else:
            nivel = "Muy debil"

        if len(contrasena) < 12:
            recomendaciones.append("Como mejora, utiliza 12 caracteres o mas.")

        return ResultadoValidacion(
            resultados=resultados,
            cumple_todo=cumple_todo,
            porcentaje=porcentaje,
            nivel=nivel,
            recomendaciones=recomendaciones,
        )


# -----------------------------------------------------------------------------
# 2. SERVICIOS CRIPTOGRAFICOS: hash no reversible y cifrado reversible
# -----------------------------------------------------------------------------


class ServicioSeguridad:
    """Genera/verifica hashes y cifra/descifra textos de demostracion."""

    PBKDF2_ITERACIONES = 600_000
    HASH_ALGORITMO = "sha256"
    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1
    DATOS_ASOCIADOS = b"ValidadorContrasenas-GUI-v1"

    @classmethod
    def generar_hash(cls, contrasena: str) -> str:
        if not contrasena:
            raise ValueError("Escribe una contrasena antes de generar el hash.")
        sal = secrets.token_bytes(16)
        derivado = hashlib.pbkdf2_hmac(
            cls.HASH_ALGORITMO,
            contrasena.encode("utf-8"),
            sal,
            cls.PBKDF2_ITERACIONES,
            dklen=32,
        )
        sal_texto = base64.urlsafe_b64encode(sal).decode("ascii")
        hash_texto = base64.urlsafe_b64encode(derivado).decode("ascii")
        return f"PBKDF2_SHA256${cls.PBKDF2_ITERACIONES}${sal_texto}${hash_texto}"

    @classmethod
    def verificar_hash(cls, contrasena: str, hash_guardado: str) -> bool:
        try:
            algoritmo, iteraciones_texto, sal_texto, hash_texto = hash_guardado.split("$")
            if algoritmo != "PBKDF2_SHA256":
                return False
            iteraciones = int(iteraciones_texto)
            if not 100_000 <= iteraciones <= 5_000_000:
                return False
            sal = base64.urlsafe_b64decode(sal_texto.encode("ascii"))
            hash_original = base64.urlsafe_b64decode(hash_texto.encode("ascii"))
            hash_calculado = hashlib.pbkdf2_hmac(
                cls.HASH_ALGORITMO,
                contrasena.encode("utf-8"),
                sal,
                iteraciones,
                dklen=len(hash_original),
            )
            return hmac.compare_digest(hash_calculado, hash_original)
        except (ValueError, TypeError, UnicodeError):
            return False

    @classmethod
    def _derivar_clave_cifrado(cls, clave_maestra: str, sal: bytes) -> bytes:
        if len(clave_maestra) < 8:
            raise ValueError("La clave maestra debe tener al menos 8 caracteres.")
        return hashlib.scrypt(
            clave_maestra.encode("utf-8"),
            salt=sal,
            n=cls.SCRYPT_N,
            r=cls.SCRYPT_R,
            p=cls.SCRYPT_P,
            dklen=32,
        )

    @classmethod
    def cifrar_texto(cls, texto: str, clave_maestra: str) -> str:
        if AESGCM is None:
            raise RuntimeError("Falta la dependencia cryptography. Instala: pip install cryptography")
        if not texto:
            raise ValueError("Escribe el texto que deseas cifrar.")
        sal = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)  # Tamano recomendado para AES-GCM.
        clave = cls._derivar_clave_cifrado(clave_maestra, sal)
        cifrador = AESGCM(clave)
        contenido_cifrado = cifrador.encrypt(
            nonce,
            texto.encode("utf-8"),
            cls.DATOS_ASOCIADOS,
        )

        partes = (
            "AESGCM_V1",
            base64.urlsafe_b64encode(sal).decode("ascii"),
            base64.urlsafe_b64encode(nonce).decode("ascii"),
            base64.urlsafe_b64encode(contenido_cifrado).decode("ascii"),
        )
        return "$".join(partes)

    @classmethod
    def descifrar_texto(cls, token: str, clave_maestra: str) -> str:
        if AESGCM is None:
            raise RuntimeError("Falta la dependencia cryptography. Instala: pip install cryptography")
        try:
            version, sal_texto, nonce_texto, contenido_texto = token.strip().split("$")
            if version != "AESGCM_V1":
                raise ValueError("El formato del texto cifrado no es reconocido.")
            sal = base64.urlsafe_b64decode(sal_texto.encode("ascii"))
            nonce = base64.urlsafe_b64decode(nonce_texto.encode("ascii"))
            contenido_cifrado = base64.urlsafe_b64decode(contenido_texto.encode("ascii"))
            if len(sal) != 16 or len(nonce) != 12:
                raise ValueError("El texto cifrado esta incompleto o fue modificado.")
            clave = cls._derivar_clave_cifrado(clave_maestra, sal)
            descifrador = AESGCM(clave)
            texto = descifrador.decrypt(
                nonce,
                contenido_cifrado,
                cls.DATOS_ASOCIADOS,
            )
            return texto.decode("utf-8")
        except InvalidTag as error:
            raise ValueError("No se pudo descifrar. Comprueba la clave maestra o el contenido.") from error
        except (ValueError, TypeError, UnicodeError) as error:
            if isinstance(error, ValueError) and str(error).startswith("No se pudo descifrar"):
                raise
            raise ValueError("El texto cifrado no es valido o esta incompleto.") from error


# -----------------------------------------------------------------------------
# 3. MONITOR DE RECURSOS DEL PROCESO
# -----------------------------------------------------------------------------


class MonitorRecursos:
    def __init__(self, max_muestras: int = 60) -> None:
        self._proceso = psutil.Process(os.getpid()) if psutil else None
        if self._proceso:
            self._proceso.cpu_percent(interval=None)  # Inicializa la medicion.
        self.muestras: Deque[Tuple[str, float, float]] = deque(maxlen=max_muestras)

    @property
    def disponible(self) -> bool:
        return self._proceso is not None

    def tomar_muestra(self) -> Tuple[float, float]:
        if not self._proceso:
            return 0.0, 0.0
        try:
            cpu = max(0.0, min(100.0, self._proceso.cpu_percent(interval=None)))
            memoria_mb = self._proceso.memory_info().rss / (1024 * 1024)
            marca_tiempo = time.strftime("%H:%M:%S")
            self.muestras.append((marca_tiempo, cpu, memoria_mb))
            return cpu, memoria_mb
        except (psutil.Error, OSError):
            return 0.0, 0.0


# -----------------------------------------------------------------------------
# 4. INTERFAZ GRAFICA
# -----------------------------------------------------------------------------


class AplicacionValidador:
    VERDE = "#087D42"
    VERDE_OSCURO = "#075B35"
    VERDE_CLARO = "#E8F5EC"
    FONDO = "#F4F7F5"
    TEXTO = "#17231C"
    GRIS = "#647168"
    ROJO = "#B42318"
    BLANCO = "#FFFFFF"

    def __init__(self, ventana: tk.Tk) -> None:
        self.ventana = ventana
        self.ventana.title("Validador de Contraseñas | Proyecto Final")
        self.ventana.geometry("1120x790")
        self.ventana.minsize(920, 680)
        self.ventana.configure(bg=self.FONDO)

        reglas = [
            ReglaLongitud(8),
            ReglaMayuscula(),
            ReglaMinuscula(),
            ReglaNumero(),
            ReglaCaracterEspecial(),
        ]
        self.validador = ValidadorContrasenas(reglas)
        self.servicio_seguridad = ServicioSeguridad()
        self.monitor = MonitorRecursos()

        self.hash_actual: Optional[str] = None
        self.intentos_restantes = 3
        self.max_intentos = 3
        self.tiempos_operaciones: Deque[Tuple[str, float]] = deque(maxlen=8)

        self.contrasena_var = tk.StringVar()
        self.mostrar_contrasena_var = tk.BooleanVar(value=False)
        self.hash_contrasena_var = tk.StringVar()
        self.cifrado_texto_var = tk.StringVar()
        self.clave_maestra_var = tk.StringVar()
        self.mostrar_clave_var = tk.BooleanVar(value=False)

        self._configurar_estilos()
        self._crear_interfaz()
        self._actualizar_estado_dependencias()
        self.ventana.protocol("WM_DELETE_WINDOW", self.cerrar)
        self.ventana.after(800, self._actualizar_recursos)

    # ----- Estilos y estructura general -------------------------------------

    def _configurar_estilos(self) -> None:
        estilo = ttk.Style()
        try:
            estilo.theme_use("clam")
        except tk.TclError:
            pass
        estilo.configure("TFrame", background=self.FONDO)
        estilo.configure("Card.TFrame", background=self.BLANCO)
        estilo.configure("TLabel", background=self.FONDO, foreground=self.TEXTO, font=("Segoe UI", 10))
        estilo.configure("Title.TLabel", background=self.VERDE, foreground=self.BLANCO, font=("Segoe UI", 19, "bold"))
        estilo.configure("Subtitle.TLabel", background=self.FONDO, foreground=self.GRIS, font=("Segoe UI", 10))
        estilo.configure("Section.TLabel", background=self.BLANCO, foreground=self.VERDE_OSCURO, font=("Segoe UI", 12, "bold"))
        estilo.configure("Card.TLabel", background=self.BLANCO, foreground=self.TEXTO, font=("Segoe UI", 10))
        estilo.configure("Small.TLabel", background=self.BLANCO, foreground=self.GRIS, font=("Segoe UI", 9))
        estilo.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(12, 8))
        estilo.configure("Primary.TButton", background=self.VERDE, foreground=self.BLANCO)
        estilo.map("Primary.TButton", background=[("active", self.VERDE_OSCURO), ("disabled", "#AAB8AF")])
        estilo.configure("Secondary.TButton", background="#E3ECE6", foreground=self.VERDE_OSCURO)
        estilo.map("Secondary.TButton", background=[("active", "#D1E2D6")])
        estilo.configure("TNotebook", background=self.FONDO, borderwidth=0)
        estilo.configure("TNotebook.Tab", padding=(18, 10), font=("Segoe UI", 10, "bold"))
        estilo.map("TNotebook.Tab", background=[("selected", self.BLANCO)], foreground=[("selected", self.VERDE_OSCURO)])
        estilo.configure("Horizontal.TProgressbar", troughcolor="#DFE8E1", background=self.VERDE)

    def _crear_interfaz(self) -> None:
        encabezado = tk.Frame(self.ventana, bg=self.VERDE, height=92)
        encabezado.pack(fill="x")
        encabezado.pack_propagate(False)

        tk.Label(
            encabezado,
            text="🔐  VALIDADOR DE CONTRASEÑAS",
            bg=self.VERDE,
            fg=self.BLANCO,
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w", padx=26, pady=(15, 2))
        tk.Label(
            encabezado,
            text="Proyecto final · Lógica de Programación II · POO y seguridad digital",
            bg=self.VERDE,
            fg="#E7F5EB",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=29)

        barra_info = tk.Frame(self.ventana, bg=self.FONDO)
        barra_info.pack(fill="x", padx=24, pady=(12, 6))
        tk.Label(
            barra_info,
            text="Jeison Moreno Bertel  |  Luis Felipe Uribe Mesa",
            bg=self.FONDO,
            fg=self.GRIS,
            font=("Segoe UI", 9),
        ).pack(anchor="e")

        self.notebook = ttk.Notebook(self.ventana)
        self.notebook.pack(fill="both", expand=True, padx=22, pady=(4, 18))

        self.tab_validacion = ttk.Frame(self.notebook, padding=18)
        self.tab_hash = ttk.Frame(self.notebook, padding=18)
        self.tab_cifrado = ttk.Frame(self.notebook, padding=18)
        self.tab_rendimiento = ttk.Frame(self.notebook, padding=18)

        self.notebook.add(self.tab_validacion, text="  Validador  ")
        self.notebook.add(self.tab_hash, text="  Hash  ")
        self.notebook.add(self.tab_cifrado, text="  Cifrado AES  ")
        self.notebook.add(self.tab_rendimiento, text="  Rendimiento  ")

        self._crear_tab_validacion()
        self._crear_tab_hash()
        self._crear_tab_cifrado()
        self._crear_tab_rendimiento()
        self._crear_menu_interactivo()

    def _crear_menu_interactivo(self) -> None:
        """Crea un menu superior para navegar por las secciones de la GUI."""
        barra = tk.Menu(self.ventana)
        menu_secciones = tk.Menu(barra, tearoff=False)
        menu_secciones.add_command(label="Validador de contraseñas", command=lambda: self.notebook.select(self.tab_validacion))
        menu_secciones.add_command(label="Hash y verificación", command=lambda: self.notebook.select(self.tab_hash))
        menu_secciones.add_command(label="Cifrado AES-GCM", command=lambda: self.notebook.select(self.tab_cifrado))
        menu_secciones.add_command(label="Consumo de recursos", command=lambda: self.notebook.select(self.tab_rendimiento))
        barra.add_cascade(label="Secciones", menu=menu_secciones)

        menu_ayuda = tk.Menu(barra, tearoff=False)
        menu_ayuda.add_command(
            label="Acerca del proyecto",
            command=lambda: messagebox.showinfo(
                "Acerca del proyecto",
                "Validador de Contraseñas\nProyecto final de Lógica de Programación II\n\n"
                "Incluye GUI, POO, validación, PBKDF2-HMAC-SHA256, cifrado AES-GCM y monitoreo de recursos.\n\n"
                "Autores: Jeison Moreno Bertel y Luis Felipe Uribe Mesa.",
            ),
        )
        barra.add_cascade(label="Ayuda", menu=menu_ayuda)
        self.ventana.configure(menu=barra)

    def _crear_tarjeta(self, padre: tk.Widget, padding: int = 16) -> tk.Frame:
        tarjeta = tk.Frame(padre, bg=self.BLANCO, highlightbackground="#DDE7E0", highlightthickness=1)
        tarjeta.configure(padx=padding, pady=padding)
        return tarjeta

    # ----- Pestaña 1: validador ---------------------------------------------

    def _crear_tab_validacion(self) -> None:
        self.tab_validacion.columnconfigure(0, weight=3)
        self.tab_validacion.columnconfigure(1, weight=2)
        self.tab_validacion.rowconfigure(0, weight=1)

        izquierda = self._crear_tarjeta(self.tab_validacion)
        izquierda.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        derecha = self._crear_tarjeta(self.tab_validacion)
        derecha.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        tk.Label(izquierda, text="Comprueba la seguridad de tu contraseña", bg=self.BLANCO, fg=self.VERDE_OSCURO, font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(izquierda, text="Escribe una contraseña y revisa los requisitos que cumple.", bg=self.BLANCO, fg=self.GRIS, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 18))

        tk.Label(izquierda, text="Contraseña", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        fila_entrada = tk.Frame(izquierda, bg=self.BLANCO)
        fila_entrada.pack(fill="x", pady=(6, 12))
        self.entrada_contrasena = ttk.Entry(fila_entrada, textvariable=self.contrasena_var, show="●", font=("Segoe UI", 12))
        self.entrada_contrasena.pack(side="left", fill="x", expand=True, ipady=7)
        ttk.Checkbutton(fila_entrada, text="Mostrar", variable=self.mostrar_contrasena_var, command=self._alternar_visibilidad).pack(side="left", padx=(9, 0))

        botones = tk.Frame(izquierda, bg=self.BLANCO)
        botones.pack(fill="x", pady=(0, 18))
        ttk.Button(botones, text="Validar contraseña", style="Primary.TButton", command=self.validar_contrasena).pack(side="left")
        ttk.Button(botones, text="Limpiar", style="Secondary.TButton", command=self.limpiar_validacion).pack(side="left", padx=8)

        tk.Label(izquierda, text="Requisitos de seguridad", bg=self.BLANCO, fg=self.VERDE_OSCURO, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        self.marco_reglas = tk.Frame(izquierda, bg=self.BLANCO)
        self.marco_reglas.pack(fill="x")
        self.etiquetas_reglas: List[tk.Label] = []
        for regla in self.validador.reglas:
            fila = tk.Frame(self.marco_reglas, bg=self.BLANCO)
            fila.pack(fill="x", pady=4)
            indicador = tk.Label(fila, text="○", bg=self.BLANCO, fg=self.GRIS, font=("Segoe UI", 13, "bold"), width=2)
            indicador.pack(side="left")
            detalle = tk.Label(fila, text=f"{regla.nombre} — {regla.descripcion}", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 9), anchor="w")
            detalle.pack(side="left", fill="x", expand=True)
            self.etiquetas_reglas.append(indicador)

        tk.Label(derecha, text="Resultado", bg=self.BLANCO, fg=self.VERDE_OSCURO, font=("Segoe UI", 15, "bold")).pack(anchor="w")
        self.nivel_label = tk.Label(derecha, text="Aún no validada", bg=self.BLANCO, fg=self.GRIS, font=("Segoe UI", 16, "bold"))
        self.nivel_label.pack(anchor="w", pady=(22, 6))
        self.porcentaje_label = tk.Label(derecha, text="0 % de requisitos cumplidos", bg=self.BLANCO, fg=self.GRIS, font=("Segoe UI", 9))
        self.porcentaje_label.pack(anchor="w")
        self.barra_seguridad = ttk.Progressbar(derecha, maximum=100, style="Horizontal.TProgressbar")
        self.barra_seguridad.pack(fill="x", pady=(9, 22))

        tk.Label(derecha, text="Recomendaciones", bg=self.BLANCO, fg=self.VERDE_OSCURO, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.recomendaciones_texto = tk.Label(
            derecha,
            text="Los resultados aparecerán aquí después de validar.",
            bg=self.BLANCO,
            fg=self.GRIS,
            font=("Segoe UI", 9),
            justify="left",
            anchor="nw",
            wraplength=300,
        )
        self.recomendaciones_texto.pack(fill="both", expand=True, anchor="nw", pady=(8, 0))

        tk.Label(
            derecha,
            text="Consejo: una contraseña larga y única ofrece una mejor protección.",
            bg=self.VERDE_CLARO,
            fg=self.VERDE_OSCURO,
            font=("Segoe UI", 9),
            wraplength=300,
            justify="left",
            padx=10,
            pady=10,
        ).pack(fill="x", pady=(12, 0))

    def _alternar_visibilidad(self) -> None:
        self.entrada_contrasena.configure(show="" if self.mostrar_contrasena_var.get() else "●")

    def validar_contrasena(self) -> None:
        contrasena = self.contrasena_var.get()
        if not contrasena:
            messagebox.showwarning("Dato requerido", "Escribe una contraseña para realizar la validación.")
            return

        inicio = time.perf_counter()
        resultado = self.validador.evaluar(contrasena)
        duracion_ms = (time.perf_counter() - inicio) * 1000
        self._registrar_operacion("Validación", duracion_ms)

        self.barra_seguridad["value"] = resultado.porcentaje
        self.porcentaje_label.configure(text=f"{resultado.porcentaje} % de requisitos cumplidos")
        color_nivel = self.VERDE if resultado.cumple_todo else ("#B7791F" if resultado.porcentaje >= 60 else self.ROJO)
        self.nivel_label.configure(text=resultado.nivel, fg=color_nivel)

        for etiqueta, (_, _, cumple) in zip(self.etiquetas_reglas, resultado.resultados):
            etiqueta.configure(text="✓" if cumple else "✕", fg=self.VERDE if cumple else self.ROJO)

        if resultado.cumple_todo:
            texto = "La contraseña cumple todos los requisitos establecidos."
        else:
            texto = "Para mejorarla, revisa lo siguiente:\n\n" + "\n".join(f"• {item}" for item in resultado.recomendaciones)
        self.recomendaciones_texto.configure(text=texto, fg=self.TEXTO)

    def limpiar_validacion(self) -> None:
        self.contrasena_var.set("")
        self.barra_seguridad["value"] = 0
        self.nivel_label.configure(text="Aún no validada", fg=self.GRIS)
        self.porcentaje_label.configure(text="0 % de requisitos cumplidos")
        self.recomendaciones_texto.configure(text="Los resultados aparecerán aquí después de validar.", fg=self.GRIS)
        for etiqueta in self.etiquetas_reglas:
            etiqueta.configure(text="○", fg=self.GRIS)
        self.entrada_contrasena.focus_set()

    # ----- Pestaña 2: hash ----------------------------------------------------

    def _crear_tab_hash(self) -> None:
        contenedor = self._crear_tarjeta(self.tab_hash)
        contenedor.pack(fill="both", expand=True)
        tk.Label(contenedor, text="Hash de contraseñas", bg=self.BLANCO, fg=self.VERDE_OSCURO, font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(
            contenedor,
            text="Genera una representación no reversible con PBKDF2-HMAC-SHA256 y una sal aleatoria.",
            bg=self.BLANCO,
            fg=self.GRIS,
            font=("Segoe UI", 9),
            wraplength=850,
        ).pack(anchor="w", pady=(4, 18))

        tk.Label(contenedor, text="Contraseña para generar o verificar", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.entrada_hash = ttk.Entry(contenedor, textvariable=self.hash_contrasena_var, show="●", font=("Segoe UI", 11))
        self.entrada_hash.pack(fill="x", pady=(6, 12), ipady=6)

        fila_botones = tk.Frame(contenedor, bg=self.BLANCO)
        fila_botones.pack(anchor="w", pady=(0, 16))
        ttk.Button(fila_botones, text="Generar hash", style="Primary.TButton", command=self.generar_hash).pack(side="left")
        ttk.Button(fila_botones, text="Verificar contraseña", style="Secondary.TButton", command=self.verificar_hash).pack(side="left", padx=8)
        ttk.Button(fila_botones, text="Limpiar", style="Secondary.TButton", command=self.limpiar_hash).pack(side="left")

        tk.Label(contenedor, text="Hash generado", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hash_salida = tk.Text(contenedor, height=4, wrap="word", font=("Consolas", 9), bg="#F7FAF8", fg=self.TEXTO, relief="solid", bd=1)
        self.hash_salida.pack(fill="x", pady=(6, 10))
        self.hash_salida.configure(state="disabled")

        self.estado_hash = tk.Label(contenedor, text="Genera un hash para habilitar la verificación.", bg=self.BLANCO, fg=self.GRIS, font=("Segoe UI", 10), justify="left", wraplength=850)
        self.estado_hash.pack(anchor="w", pady=(4, 8))
        self.intentos_label = tk.Label(contenedor, text="Intentos disponibles: 3", bg=self.BLANCO, fg=self.GRIS, font=("Segoe UI", 9, "bold"))
        self.intentos_label.pack(anchor="w")

        tk.Label(
            contenedor,
            text="Importante: este ejemplo conserva el hash únicamente en la memoria de la aplicación. No guarda contraseñas ni hashes en una base de datos.",
            bg=self.VERDE_CLARO,
            fg=self.VERDE_OSCURO,
            font=("Segoe UI", 9),
            wraplength=850,
            justify="left",
            padx=10,
            pady=10,
        ).pack(fill="x", pady=(18, 0))

    def _mostrar_hash(self, valor: str) -> None:
        self.hash_salida.configure(state="normal")
        self.hash_salida.delete("1.0", "end")
        self.hash_salida.insert("1.0", valor)
        self.hash_salida.configure(state="disabled")

    def generar_hash(self) -> None:
        contrasena = self.hash_contrasena_var.get()
        try:
            inicio = time.perf_counter()
            self.hash_actual = self.servicio_seguridad.generar_hash(contrasena)
            duracion_ms = (time.perf_counter() - inicio) * 1000
            self._registrar_operacion("Hash PBKDF2", duracion_ms)
            self._mostrar_hash(self.hash_actual)
            self.intentos_restantes = self.max_intentos
            self._actualizar_intentos()
            self.estado_hash.configure(text=f"Hash generado correctamente. Tiempo: {duracion_ms:.2f} ms. Ahora puedes cambiar el campo y comprobar una contraseña.", fg=self.VERDE)
        except (ValueError, RuntimeError) as error:
            messagebox.showerror("No se pudo generar el hash", str(error))

    def verificar_hash(self) -> None:
        if not self.hash_actual:
            messagebox.showwarning("Hash no disponible", "Primero genera un hash.")
            return
        if self.intentos_restantes <= 0:
            messagebox.showerror("Verificación bloqueada", "Se agotaron los tres intentos. Genera un nuevo hash para reiniciar la demostración.")
            return

        contrasena = self.hash_contrasena_var.get()
        inicio = time.perf_counter()
        coincide = self.servicio_seguridad.verificar_hash(contrasena, self.hash_actual)
        duracion_ms = (time.perf_counter() - inicio) * 1000
        self._registrar_operacion("Verificar hash", duracion_ms)

        if coincide:
            self.estado_hash.configure(text=f"✓ Verificación correcta. La contraseña coincide con el hash. ({duracion_ms:.2f} ms)", fg=self.VERDE)
            self.intentos_restantes = self.max_intentos
        else:
            self.intentos_restantes -= 1
            if self.intentos_restantes == 0:
                self.estado_hash.configure(text="✕ Contraseña incorrecta. Se agotaron los intentos y la verificación quedó bloqueada.", fg=self.ROJO)
            else:
                self.estado_hash.configure(text=f"✕ La contraseña no coincide. Tiempo: {duracion_ms:.2f} ms.", fg=self.ROJO)
        self._actualizar_intentos()

    def _actualizar_intentos(self) -> None:
        self.intentos_label.configure(text=f"Intentos disponibles: {self.intentos_restantes}")

    def limpiar_hash(self) -> None:
        self.hash_contrasena_var.set("")
        self.hash_actual = None
        self.intentos_restantes = self.max_intentos
        self._mostrar_hash("")
        self.estado_hash.configure(text="Genera un hash para habilitar la verificación.", fg=self.GRIS)
        self._actualizar_intentos()

    # ----- Pestaña 3: cifrado AES-GCM ----------------------------------------

    def _crear_tab_cifrado(self) -> None:
        contenedor = self._crear_tarjeta(self.tab_cifrado)
        contenedor.pack(fill="both", expand=True)
        tk.Label(contenedor, text="Cifrado y descifrado AES-GCM", bg=self.BLANCO, fg=self.VERDE_OSCURO, font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(
            contenedor,
            text="Demostración de cifrado reversible. La clave se deriva de una contraseña maestra mediante Scrypt.",
            bg=self.BLANCO,
            fg=self.GRIS,
            font=("Segoe UI", 9),
            wraplength=850,
        ).pack(anchor="w", pady=(4, 16))

        tk.Label(contenedor, text="Contraseña o texto que deseas cifrar", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.entrada_cifrado = ttk.Entry(contenedor, textvariable=self.cifrado_texto_var, font=("Segoe UI", 11))
        self.entrada_cifrado.pack(fill="x", pady=(6, 12), ipady=6)

        tk.Label(contenedor, text="Contraseña maestra (minimo 8 caracteres)", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        fila_clave = tk.Frame(contenedor, bg=self.BLANCO)
        fila_clave.pack(fill="x", pady=(6, 14))
        self.entrada_clave = ttk.Entry(fila_clave, textvariable=self.clave_maestra_var, show="●", font=("Segoe UI", 11))
        self.entrada_clave.pack(side="left", fill="x", expand=True, ipady=6)
        ttk.Checkbutton(fila_clave, text="Mostrar", variable=self.mostrar_clave_var, command=self._alternar_clave).pack(side="left", padx=(9, 0))

        fila_botones = tk.Frame(contenedor, bg=self.BLANCO)
        fila_botones.pack(anchor="w", pady=(0, 14))
        ttk.Button(fila_botones, text="Cifrar texto", style="Primary.TButton", command=self.cifrar).pack(side="left")
        ttk.Button(fila_botones, text="Descifrar contenido", style="Secondary.TButton", command=self.descifrar).pack(side="left", padx=8)
        ttk.Button(fila_botones, text="Limpiar", style="Secondary.TButton", command=self.limpiar_cifrado).pack(side="left")

        tk.Label(contenedor, text="Contenido cifrado (puedes pegar aquí un token anterior)", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.token_salida = tk.Text(contenedor, height=5, wrap="word", font=("Consolas", 9), bg="#F7FAF8", fg=self.TEXTO, relief="solid", bd=1)
        self.token_salida.pack(fill="x", pady=(6, 10))

        tk.Label(contenedor, text="Resultado del descifrado", bg=self.BLANCO, fg=self.TEXTO, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.resultado_descifrado = tk.Label(contenedor, text="Aquí aparecerá el texto original si la clave es correcta.", bg="#F7FAF8", fg=self.GRIS, font=("Segoe UI", 10), justify="left", anchor="w", wraplength=850, padx=10, pady=10)
        self.resultado_descifrado.pack(fill="x", pady=(6, 0))

        tk.Label(
            contenedor,
            text="Hash y cifrado no son lo mismo: el hash no se puede revertir; AES-GCM permite recuperar el texto original usando la clave correcta.",
            bg=self.VERDE_CLARO,
            fg=self.VERDE_OSCURO,
            font=("Segoe UI", 9),
            wraplength=850,
            justify="left",
            padx=10,
            pady=10,
        ).pack(fill="x", pady=(14, 0))

    def _alternar_clave(self) -> None:
        self.entrada_clave.configure(show="" if self.mostrar_clave_var.get() else "●")

    def cifrar(self) -> None:
        texto = self.cifrado_texto_var.get()
        clave = self.clave_maestra_var.get()
        try:
            inicio = time.perf_counter()
            token = self.servicio_seguridad.cifrar_texto(texto, clave)
            duracion_ms = (time.perf_counter() - inicio) * 1000
            self._registrar_operacion("Cifrado AES-GCM", duracion_ms)
            self.token_salida.delete("1.0", "end")
            self.token_salida.insert("1.0", token)
            self.resultado_descifrado.configure(text=f"Texto cifrado correctamente. Tiempo: {duracion_ms:.2f} ms.", fg=self.VERDE)
        except (ValueError, RuntimeError) as error:
            messagebox.showerror("No se pudo cifrar", str(error))

    def descifrar(self) -> None:
        token = self.token_salida.get("1.0", "end").strip()
        clave = self.clave_maestra_var.get()
        try:
            inicio = time.perf_counter()
            texto = self.servicio_seguridad.descifrar_texto(token, clave)
            duracion_ms = (time.perf_counter() - inicio) * 1000
            self._registrar_operacion("Descifrado AES-GCM", duracion_ms)
            self.resultado_descifrado.configure(text=f"{texto}\n\nDescifrado correcto · {duracion_ms:.2f} ms", fg=self.VERDE)
        except (ValueError, RuntimeError) as error:
            self.resultado_descifrado.configure(text="No se pudo descifrar el contenido.", fg=self.ROJO)
            messagebox.showerror("Error de descifrado", str(error))

    def limpiar_cifrado(self) -> None:
        self.cifrado_texto_var.set("")
        self.clave_maestra_var.set("")
        self.token_salida.delete("1.0", "end")
        self.resultado_descifrado.configure(text="Aquí aparecerá el texto original si la clave es correcta.", fg=self.GRIS)

    # ----- Pestaña 4: recursos y graficas ------------------------------------

    def _crear_tab_rendimiento(self) -> None:
        self.tab_rendimiento.columnconfigure(0, weight=1)
        self.tab_rendimiento.columnconfigure(1, weight=1)
        self.tab_rendimiento.rowconfigure(3, weight=1)
        self.tab_rendimiento.rowconfigure(5, weight=1)

        tk.Label(self.tab_rendimiento, text="Consumo de recursos y tiempos de ejecución", bg=self.FONDO, fg=self.VERDE_OSCURO, font=("Segoe UI", 15, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        tk.Label(
            self.tab_rendimiento,
            text="Las gráficas se actualizan mientras la aplicación está abierta. Las operaciones registran su duración en milisegundos.",
            bg=self.FONDO,
            fg=self.GRIS,
            font=("Segoe UI", 9),
            wraplength=850,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        self.cpu_valor = tk.Label(self.tab_rendimiento, text="CPU: -- %", bg=self.FONDO, fg=self.VERDE_OSCURO, font=("Segoe UI", 10, "bold"))
        self.cpu_valor.grid(row=2, column=0, sticky="w")
        self.ram_valor = tk.Label(self.tab_rendimiento, text="RAM del proceso: -- MB", bg=self.FONDO, fg=self.VERDE_OSCURO, font=("Segoe UI", 10, "bold"))
        self.ram_valor.grid(row=2, column=1, sticky="w")

        self.canvas_cpu = tk.Canvas(self.tab_rendimiento, height=150, bg=self.BLANCO, highlightthickness=1, highlightbackground="#DDE7E0")
        self.canvas_cpu.grid(row=3, column=0, sticky="nsew", padx=(0, 7), pady=(7, 14))
        self.canvas_ram = tk.Canvas(self.tab_rendimiento, height=150, bg=self.BLANCO, highlightthickness=1, highlightbackground="#DDE7E0")
        self.canvas_ram.grid(row=3, column=1, sticky="nsew", padx=(7, 0), pady=(7, 14))

        tk.Label(self.tab_rendimiento, text="Tiempo por operación (ms)", bg=self.FONDO, fg=self.VERDE_OSCURO, font=("Segoe UI", 11, "bold")).grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 6))
        self.canvas_tiempos = tk.Canvas(self.tab_rendimiento, height=190, bg=self.BLANCO, highlightthickness=1, highlightbackground="#DDE7E0")
        self.canvas_tiempos.grid(row=5, column=0, columnspan=2, sticky="nsew")

        self.nota_recursos = tk.Label(
            self.tab_rendimiento,
            text="",
            bg=self.FONDO,
            fg=self.GRIS,
            font=("Segoe UI", 8),
            justify="left",
            wraplength=850,
        )
        self.nota_recursos.grid(row=6, column=0, columnspan=2, sticky="w", pady=(9, 0))

        if not self.monitor.disponible:
            self.nota_recursos.configure(text="Para medir CPU y memoria RAM instala psutil: pip install psutil")
        else:
            self.nota_recursos.configure(text="CPU: porcentaje de uso del proceso. RAM: memoria residente (RSS) utilizada por esta aplicación.")

        if AESGCM is None:
            nota = "La pestaña de cifrado requiere cryptography: pip install cryptography"
            self.nota_recursos.configure(text=(self.nota_recursos.cget("text") + "  |  " + nota).strip(" |"))

        self.canvas_cpu.bind("<Configure>", lambda _evento: self._dibujar_graficas())
        self.canvas_ram.bind("<Configure>", lambda _evento: self._dibujar_graficas())
        self.canvas_tiempos.bind("<Configure>", lambda _evento: self._dibujar_graficas())

    def _registrar_operacion(self, nombre: str, duracion_ms: float) -> None:
        self.tiempos_operaciones.append((nombre, max(0.0, duracion_ms)))
        # Toma una muestra adicional al terminar cada operacion para registrar
        # tambien el comportamiento del proceso durante pruebas cortas.
        if self.monitor.disponible:
            cpu, memoria = self.monitor.tomar_muestra()
            self.cpu_valor.configure(text=f"CPU: {cpu:.1f} %")
            self.ram_valor.configure(text=f"RAM del proceso: {memoria:.1f} MB")
        self._dibujar_graficas()

    def _actualizar_recursos(self) -> None:
        if self.monitor.disponible:
            cpu, memoria = self.monitor.tomar_muestra()
            self.cpu_valor.configure(text=f"CPU: {cpu:.1f} %")
            self.ram_valor.configure(text=f"RAM del proceso: {memoria:.1f} MB")
            self._dibujar_graficas()
        else:
            self.cpu_valor.configure(text="CPU: requiere psutil")
            self.ram_valor.configure(text="RAM: requiere psutil")
        self.ventana.after(1000, self._actualizar_recursos)

    def _dibujar_graficas(self) -> None:
        self._dibujar_linea(
            self.canvas_cpu,
            "Uso de CPU (%)",
            [muestra[1] for muestra in self.monitor.muestras],
            maximo_fijo=100.0,
            sufijo="%",
        )
        self._dibujar_linea(
            self.canvas_ram,
            "Memoria RAM del proceso (MB)",
            [muestra[2] for muestra in self.monitor.muestras],
            maximo_fijo=None,
            sufijo=" MB",
        )
        self._dibujar_barras_tiempo()

    def _dibujar_linea(self, canvas: tk.Canvas, titulo: str, datos: Sequence[float], maximo_fijo: Optional[float], sufijo: str) -> None:
        canvas.delete("all")
        ancho = max(canvas.winfo_width(), 260)
        alto = max(canvas.winfo_height(), 130)
        margen_izq, margen_der, margen_sup, margen_inf = 42, 12, 28, 24
        canvas.create_text(12, 9, anchor="nw", text=titulo, fill=self.VERDE_OSCURO, font=("Segoe UI", 9, "bold"))

        x0, y0 = margen_izq, alto - margen_inf
        x1, y1 = ancho - margen_der, margen_sup
        canvas.create_line(x0, y1, x0, y0, fill="#AAB8AF")
        canvas.create_line(x0, y0, x1, y0, fill="#AAB8AF")

        if not datos:
            canvas.create_text((x0 + x1) / 2, (y0 + y1) / 2, text="Esperando mediciones...", fill=self.GRIS, font=("Segoe UI", 9))
            return

        maximo = maximo_fijo if maximo_fijo is not None else max(max(datos) * 1.15, 10.0)
        for fraccion in (0, 0.5, 1):
            y = y0 - fraccion * (y0 - y1)
            valor = maximo * fraccion
            canvas.create_line(x0, y, x1, y, fill="#E7EDE9", dash=(2, 3))
            canvas.create_text(x0 - 6, y, anchor="e", text=f"{valor:.0f}", fill=self.GRIS, font=("Segoe UI", 7))

        puntos: List[float] = []
        cantidad = len(datos)
        for indice, valor in enumerate(datos):
            x = x0 if cantidad == 1 else x0 + indice * (x1 - x0) / (cantidad - 1)
            y = y0 - min(valor, maximo) * (y0 - y1) / maximo
            puntos.extend([x, y])
        if len(puntos) >= 4:
            canvas.create_line(*puntos, fill=self.VERDE, width=2, smooth=True)
        for indice in range(0, len(puntos), 2):
            canvas.create_oval(puntos[indice] - 2, puntos[indice + 1] - 2, puntos[indice] + 2, puntos[indice + 1] + 2, fill=self.VERDE, outline=self.VERDE)
        canvas.create_text(x1, y1 + 2, anchor="ne", text=f"Actual: {datos[-1]:.1f}{sufijo}", fill=self.GRIS, font=("Segoe UI", 7))

    def _dibujar_barras_tiempo(self) -> None:
        canvas = self.canvas_tiempos
        canvas.delete("all")
        ancho = max(canvas.winfo_width(), 300)
        alto = max(canvas.winfo_height(), 150)
        canvas.create_text(12, 9, anchor="nw", text="Duración registrada de las últimas operaciones", fill=self.VERDE_OSCURO, font=("Segoe UI", 9, "bold"))
        if not self.tiempos_operaciones:
            canvas.create_text(ancho / 2, alto / 2, text="Realiza una validación, genera un hash o cifra un texto para ver los tiempos.", fill=self.GRIS, font=("Segoe UI", 9))
            return

        datos = list(self.tiempos_operaciones)
        maximo = max(max(valor for _, valor in datos), 1.0)
        margen_izq = 135
        margen_der = 45
        espacio_util = max(20, ancho - margen_izq - margen_der)
        alto_fila = max(18, min(27, (alto - 38) / len(datos)))
        for indice, (nombre, valor) in enumerate(datos):
            y = 32 + indice * alto_fila
            canvas.create_text(margen_izq - 8, y + 7, anchor="e", text=nombre, fill=self.TEXTO, font=("Segoe UI", 8))
            largo = (valor / maximo) * espacio_util
            canvas.create_rectangle(margen_izq, y, margen_izq + largo, y + 13, fill=self.VERDE, outline="")
            canvas.create_text(min(margen_izq + largo + 5, ancho - 5), y + 7, anchor="w" if margen_izq + largo + 38 < ancho else "e", text=f"{valor:.2f} ms", fill=self.GRIS, font=("Segoe UI", 8))

    # ----- Cierre -------------------------------------------------------------

    def _actualizar_estado_dependencias(self) -> None:
        faltantes = []
        if psutil is None:
            faltantes.append("psutil")
        if AESGCM is None:
            faltantes.append("cryptography")
        if faltantes:
            messagebox.showwarning(
                "Dependencias opcionales",
                "Algunas funciones necesitan instalar paquetes:\n\n"
                "pip install cryptography psutil\n\n"
                "La validación y el hash funcionan con la biblioteca estándar de Python.",
            )

    def cerrar(self) -> None:
        self.ventana.destroy()


def main() -> None:
    ventana = tk.Tk()
    AplicacionValidador(ventana)
    ventana.mainloop()


if __name__ == "__main__":
    main()
