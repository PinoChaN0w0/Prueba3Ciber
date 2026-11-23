"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).

Versión endurecida (hardened): mitiga SQLi, XSS reflejado, CSRF, fuerza bruta,
gestión insegura de credenciales/secretos, modo debug y cabeceras HTTP faltantes.
"""
import hmac
import os
import re
import secrets
import sqlite3
import time

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from markupsafe import escape
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

## Clave de sesión dinámica (sin secretos en el código) y cookies endurecidas.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

## Credenciales de administrador con hash robusto (scrypt/PBKDF2) sin contraseñas hardcoded.
ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_PASSWORD_HASH") or generate_password_hash(
    os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(24)
)

## Control de tasa (rate limiting) para mitigar fuerza bruta en /login.
INTENTOS_LOGIN = {}
MAX_INTENTOS_LOGIN = 5
VENTANA_LOGIN_SEG = 60

## Versión desplegada: la inyecta el pipeline (1.0.<build>+<commit>).
VERSION = os.environ.get("APP_VERSION", "dev")
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

## Patrones que delatan un intento de ataque (observabilidad en Prometheus/Grafana).
PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def conectar():
    """!
    @brief Abre (una vez por petición) la conexión a la base de datos SQLite.
    @return Conexión sqlite3 con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión a la base de datos al terminar cada petición.
    @param _error Excepción de la petición (si la hubo); no se usa.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales si está vacía.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Marca el inicio de la petición y cuenta los parámetros con patrones de ataque.
    """
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Agrega cabeceras de seguridad HTTP y registra métricas de cada petición.
    @param respuesta Respuesta que Flask enviará al cliente.
    @return Respuesta endurecida con cabeceras de seguridad.
    """
    respuesta.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    respuesta.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    respuesta.headers["Server"] = "SecureDev"

    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    return respuesta


@app.route("/")
def portada():
    """!
    @brief Portada HTML con enlaces, formularios y token anti-CSRF.
    @return Página HTML.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template_string(PORTADA, version=VERSION, csrf_token=session["csrf_token"])


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario escapando caracteres HTML para prevenir XSS reflejado.
    @return Página HTML segura con el saludo.
    """
    name = escape(request.args.get("name", "visitante"))
    return f"<h1>Hola, {name}!</h1>"


@app.route("/health")
def health():
    """!
    @brief Estado de la aplicación (lo usan el despliegue y el monitoreo).
    @return JSON {"estado": "ok"}.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Versión desplegada, para la trazabilidad.
    @return JSON con el nombre y la versión de la aplicación.
    """
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Lista todos los alumnos.
    @return JSON con la lista de alumnos.
    """
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por su identificador.
    @param alumno_id Identificador numérico del alumno.
    @return JSON con el alumno, o error 404 si no existe.
    """
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos mediante consulta parametrizada (mitiga SQL Injection).
    @return JSON con los alumnos encontrados.
    """
    nombre = request.args.get("nombre", "")
    try:
        filas = conectar().execute(
            "SELECT * FROM alumnos WHERE nombre LIKE ?",
            (f"%{nombre}%",),
        ).fetchall()
    except sqlite3.Error:
        return jsonify({"error": "Error al consultar alumnos"}), 500
    return jsonify([dict(f) for f in filas])


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Valida token anti-CSRF, límite de intentos y credenciales con hash seguro.
    @return JSON con el resultado; 403 por CSRF inválido, 429 por fuerza bruta, 401 por credenciales inválidas.
    """
    token_esperado = session.get("csrf_token", "")
    token_enviado = request.form.get("csrf_token", "")
    if not token_esperado or not hmac.compare_digest(token_enviado, token_esperado):
        LOGIN_FALLIDOS.inc()
        return jsonify({"error": "Token CSRF inválido o ausente"}), 403

    ip = request.remote_addr or "desconocido"
    ahora = time.time()
    recientes = [t for t in INTENTOS_LOGIN.get(ip, []) if ahora - t < VENTANA_LOGIN_SEG]
    if len(recientes) >= MAX_INTENTOS_LOGIN:
        INTENTOS_LOGIN[ip] = recientes
        LOGIN_FALLIDOS.inc()
        return jsonify({"error": "Demasiados intentos fallidos. Intente más tarde."}), 429

    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    if hmac.compare_digest(usuario, ADMIN_USUARIO) and check_password_hash(ADMIN_CLAVE_HASH, clave):
        INTENTOS_LOGIN.pop(ip, None)
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})

    recientes.append(ahora)
    INTENTOS_LOGIN[ip] = recientes
    LOGIN_FALLIDOS.inc()
    app.logger.warning("Login fallido para el usuario '%s' desde %s", usuario, ip)
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/metrics")
def metrics():
    """!
    @brief Métricas en formato Prometheus.
    @return Texto con las métricas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)