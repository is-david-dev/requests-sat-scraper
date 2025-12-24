"""
Clase SATPortalClient - Cliente de autenticación al Portal CFDI del SAT
========================================================================

Esta clase encapsula todo el proceso de autenticación al portal de CFDI del SAT,
facilitando su reutilización y extensión.

Ejemplo de uso básico:
    cliente = SATPortalClient()
    if cliente.login(rfc="XAXX010101000", password="tu_password", captcha="ABC123"):
        print("Login exitoso")
        # Ahora puedes usar cliente.session para hacer peticiones
        response = cliente.session.get("https://portalcfdi...")

Autor: [Tu nombre]
Fecha: 2025-12-12
"""

import base64
import getpass
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import html
from typing import Optional, Dict, Tuple


class SATPortalClient:
    """
    Cliente para autenticación y operaciones en el Portal CFDI del SAT.

    Esta clase maneja el flujo completo de autenticación WS-Federation,
    incluyendo el manejo de captchas, tokens SAML y sesiones.

    Attributes:
        session (requests.Session): Sesión HTTP con cookies de autenticación
        base_url (str): URL base del portal CFDI
        auth_url (str): URL del servidor de autenticación
        user_info (dict): Información del usuario extraída del token SAML
        is_authenticated (bool): Estado de autenticación
    """

    def __init__(self):
        """
        Inicializa el cliente del portal SAT.

        Crea una nueva sesión HTTP y configura las URLs base necesarias.
        """
        # URL del portal principal
        self.base_url = "https://portalcfdi.facturaelectronica.sat.gob.mx/"
        self.emitidas_url = "https://portalcfdi.facturaelectronica.sat.gob.mx/ConsultaEmisor.aspx"
        self.recidas_url = "https://portalcfdi.facturaelectronica.sat.gob.mx/ConsultaReceptor.aspx"
        self.logout_url = "https://portalcfdi.facturaelectronica.sat.gob.mx/logout.aspx?salir=y"

        # URL del servidor de autenticación
        self.auth_url = "https://cfdiau.sat.gob.mx"

        # Crear sesión de requests (mantiene cookies entre peticiones)
        self.session = requests.Session()

        # Información del usuario autenticado
        self.user_info = {}

        # Estado de autenticación
        self.is_authenticated = False

        # URL actual después del login
        self.current_url = None

        # Headers que simulan un navegador Chrome
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "es-MX,es;q=0.9,en-US;q=0.8,en;q=0.7",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"'
        }


    # =========================================================================
    # MÉTODOS PRIVADOS (auxiliares internos)
    # =========================================================================

    def _extract_image_base64(self, html_text: str) -> Optional[str]:
        """
        Extrae la imagen del captcha desde el HTML.

        Args:
            html_text: String con el contenido HTML

        Returns:
            String en base64 de la imagen o None si no se encuentra
        """
        soup = BeautifulSoup(html_text, "html.parser")
        captcha_img = soup.find("img")

        if not captcha_img:
            return None

        src = captcha_img.get("src", "")

        if src.startswith("data:image"):
            # Extraer solo el base64, sin el prefijo "data:image/jpeg;base64,"
            base64_data = src.split(",")[1]
            return base64_data

        return None


    def _extract_javascript_redirect(self, html_text: str) -> Optional[str]:
        """
        Extrae una URL de redirección desde código JavaScript.

        Args:
            html_text: String con el contenido HTML

        Returns:
            URL extraída o None si no se encuentra
        """
        match = re.search(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]", html_text)
        return match.group(1) if match else None


    def _extract_saml_attributes(self, wresult_value: str) -> Dict[str, str]:
        """
        Extrae los atributos del usuario desde el token SAML.

        Args:
            wresult_value: String con el token SAML (XML con entidades HTML)

        Returns:
            Diccionario con los atributos extraídos
        """
        # Decodificar entidades HTML
        saml_xml = html.unescape(wresult_value)

        attributes = {}

        # Expresión regular para capturar atributos SAML
        pattern = r'<saml:Attribute AttributeName="([^"]+)"[^>]*>.*?<saml:AttributeValue>([^<]+)</saml:AttributeValue>'
        matches = re.finditer(pattern, saml_xml, re.DOTALL)

        for match in matches:
            attr_name = match.group(1)
            attr_value = match.group(2)
            attributes[attr_name] = attr_value

        return attributes


    def _check_error_message(self, html_text: str) -> Optional[str]:
        """
        Busca mensajes de error en el HTML del SAT.

        Args:
            html_text: String con el contenido HTML

        Returns:
            Mensaje de error si existe, None si no hay error
        """
        soup = BeautifulSoup(html_text, "html.parser")

        # Buscar div de error
        error_div = soup.find("div", {"id": "divMsgError"})

        if error_div:
            style = error_div.get("style", "")

            # Si no está oculto, hay un error
            if "display: none" not in style:
                msg_error = soup.find("div", {"id": "msgError"})
                if msg_error:
                    return msg_error.get_text(strip=True)

        return None


    # =========================================================================
    # MÉTODOS PÚBLICOS
    # =========================================================================

    def get_captcha(self, save_path: str = "captcha.jpg") -> Tuple[bool, Optional[str]]:
        """
        Obtiene la imagen del captcha del portal SAT.

        Este método realiza las peticiones necesarias para llegar al formulario
        de login y extrae el captcha. Guarda la imagen en un archivo para que
        el usuario pueda verla.

        Args:
            save_path: Ruta donde guardar la imagen del captcha

        Returns:
            Tupla (éxito: bool, base64: str o None)

        Example:
            success, captcha_b64 = cliente.get_captcha()
            if success:
                print("Captcha guardado en captcha.jpg")
        """
        try:
            # Paso 1: GET inicial al portal
            resp = self.session.get(
                self.base_url,
                headers=self.headers,
                allow_redirects=False
            )

            if resp.status_code != 302:
                return False, None

            # Paso 2: Seguir redirección
            location1 = resp.headers.get("Location")
            if not location1:
                return False, None

            resp2 = self.session.get(
                location1,
                headers=self.headers,
                allow_redirects=False
            )

            # Paso 3: Procesar formulario auto-submit WS-Fed
            soup = BeautifulSoup(resp2.text, "html.parser")
            form = soup.find("form")

            if not form:
                return False, None

            action = form.get("action")
            post_url = urljoin(self.auth_url, action)

            resp3 = self.session.post(post_url, headers=self.headers, data={})

            # Guardar la respuesta para usarla después en login()
            self._login_form_response = resp3

            # Extraer captcha
            captcha_base64 = self._extract_image_base64(resp3.text)

            if captcha_base64:
                # Guardar imagen
                with open(save_path, "wb") as f:
                    f.write(base64.b64decode(captcha_base64))

                return True, captcha_base64

            return False, None

        except Exception as e:
            print(f"Error obteniendo captcha: {e}")
            return False, None


    def login(self, rfc: str, password: str, captcha: str, verbose: bool = True) -> bool:
        """
        Realiza el login completo al portal SAT.

        Este método ejecuta todo el flujo de autenticación WS-Federation,
        incluyendo el envío de credenciales y el procesamiento del token SAML.

        Args:
            rfc: RFC del contribuyente (ej: "XAXX010101000")
            password: Contraseña CIEC del SAT
            captcha: Código del captcha visible en la imagen
            verbose: Si es True, imprime mensajes de progreso

        Returns:
            True si el login fue exitoso, False en caso contrario

        Example:
            cliente = SATPortalClient()
            cliente.get_captcha()  # Guardar captcha para verlo

            if cliente.login("XAXX010101000", "mi_password", "ABC123"):
                print("Autenticado exitosamente")
                print(f"Usuario: {cliente.user_info.get('NombreUsuario')}")
        """
        try:
            if verbose:
                print("="*70)
                print("    Iniciando autenticación al Portal SAT CFDI")
                print("="*70)

            # Verificar que ya se obtuvo el captcha
            if not hasattr(self, '_login_form_response'):
                if verbose:
                    print("\n[!] Debe llamar a get_captcha() primero")
                return False

            resp3 = self._login_form_response

            # ============================================================
            # PASO 1: Analizar formulario de login
            # ============================================================
            if verbose:
                print("\n[1/5] Analizando formulario de login...")

            soup_login = BeautifulSoup(resp3.text, "html.parser")
            form_login = soup_login.find("form", {"id": "IDPLogin"})

            if not form_login:
                if verbose:
                    print("      ✗ No se encontró formulario de login")
                return False

            # Extraer campos hidden
            form_data = {}
            for input_field in form_login.find_all("input", {"type": "hidden"}):
                name = input_field.get("name")
                value = input_field.get("value", "")
                if name:
                    form_data[name] = value

            # Asignar credenciales
            form_data["Ecom_User_ID"] = rfc.strip().upper()
            form_data["Ecom_Password"] = password
            form_data["userCaptcha"] = captcha.strip().upper()
            form_data["submit"] = "Enviar"

            if verbose:
                print(f"      ✓ Credenciales preparadas para RFC: {rfc}")

            # ============================================================
            # PASO 2: Enviar credenciales
            # ============================================================
            if verbose:
                print("\n[2/5] Enviando credenciales al servidor...")

            form_action = form_login.get("action", "")
            login_url = urljoin(resp3.url, form_action) if form_action else resp3.url

            headers_post = self.headers.copy()
            headers_post.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.auth_url,
                "Referer": resp3.url,
                "Host": "cfdiau.sat.gob.mx"
            })

            resp_login = self.session.post(
                login_url,
                headers=headers_post,
                data=form_data,
                allow_redirects=False
            )

            # ============================================================
            # PASO 3: Verificar errores
            # ============================================================
            if verbose:
                print("\n[3/5] Verificando respuesta...")

            error_msg = self._check_error_message(resp_login.text)
            if error_msg:
                if verbose:
                    print(f"      ✗ Error: {error_msg}")
                return False

            if verbose:
                print("      ✓ No se detectaron errores")

            # ============================================================
            # PASO 4: Seguir redirección JavaScript y obtener SAML
            # ============================================================
            if verbose:
                print("\n[4/5] Procesando token SAML...")

            redirect_url = self._extract_javascript_redirect(resp_login.text)
            if not redirect_url:
                if verbose:
                    print("      ✗ No se encontró redirección JavaScript")
                return False

            resp_redirect = self.session.get(
                redirect_url,
                headers=self.headers,
                allow_redirects=False
            )

            # Extraer formulario SAML
            soup_saml = BeautifulSoup(resp_redirect.text, "html.parser")
            form_saml = soup_saml.find("form")

            if not form_saml:
                if verbose:
                    print("      ✗ No se encontró formulario SAML")
                return False

            # Extraer datos del formulario SAML
            saml_data = {}
            for inp in form_saml.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    saml_data[name] = value

            # Extraer información del usuario del token SAML
            if "wresult" in saml_data:
                self.user_info = self._extract_saml_attributes(saml_data["wresult"])

                if verbose and self.user_info:
                    print(f"      ✓ Usuario: {self.user_info.get('NombreUsuario', 'N/A')}")
                    print(f"      ✓ RFC: {self.user_info.get('IdUsuario', 'N/A')}")

            # ============================================================
            # PASO 5: Enviar token SAML al portal
            # ============================================================
            if verbose:
                print("\n[5/5] Estableciendo sesión en el portal...")

            saml_action = form_saml.get("action")

            headers_saml = self.headers.copy()
            headers_saml.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.auth_url,
                "Referer": redirect_url,
                "Host": "portalcfdi.facturaelectronica.sat.gob.mx"
            })

            resp_final = self.session.post(
                saml_action,
                data=saml_data,
                headers=headers_saml,
                allow_redirects=True
            )

            # Guardar URL actual
            self.current_url = resp_final.url

            # Marcar como autenticado
            self.is_authenticated = True

            if verbose:
                print("\n" + "="*70)
                print("✅ AUTENTICACIÓN EXITOSA")
                print("="*70)
                print(f"\nUsuario: {self.user_info.get('NombreUsuario', 'N/A')}")
                print(f"RFC: {self.user_info.get('IdUsuario', 'N/A')}")
                print(f"Tipo: {self.user_info.get('TipoContribuyente', 'N/A')}")
                print(f"URL actual: {self.current_url}")
                print("\n✓ Sesión establecida correctamente")

            return True

        except Exception as e:
            if verbose:
                print(f"\n✗ Error durante el login: {e}")
            return False


    def login_interactive(self) -> bool:
        """
        Realiza login de forma interactiva, solicitando datos al usuario.

        Este método es útil para uso en consola/terminal, donde el usuario
        puede ingresar sus credenciales manualmente.

        Returns:
            True si el login fue exitoso, False en caso contrario

        Example:
            cliente = SATPortalClient()
            if cliente.login_interactive():
                print("¡Login exitoso!")
        """
        print("="*70)
        print("    AUTENTICACIÓN INTERACTIVA - PORTAL SAT CFDI")
        print("="*70)

        # Obtener captcha
        print("\n[*] Obteniendo captcha del servidor...")
        success, _ = self.get_captcha()

        if not success:
            print("✗ Error: No se pudo obtener el captcha")
            return False

        print("✓ Captcha guardado en 'captcha.jpg'")
        print("\n⚠️  IMPORTANTE: Revise el archivo captcha.jpg antes de continuar\n")

        # Solicitar credenciales
        # rfc = input("RFC (ej: XAXX010101000): ").strip().upper()
        # password = getpass.getpass("Contraseña CIEC: ")
        # captcha = input("Captcha (como aparece en la imagen): ").strip().upper()
        rfc = "CUGD010514TQ8"
        password = "Daviarex"
        captcha = input("Captcha (como aparece en la imagen): ").strip().upper()

        # Realizar login
        return self.login(rfc, password, captcha, verbose=True)


    def redirect_facturas_emitidas(self):
        """
        Realiza el direccionamiento a la pagina donde estan las facturas emitidas

        Returns:
            True si el redireccionamiento fue exitoso, False en caso contrario
        """
        resp_emitidas = self.session.get(self.emitidas_url)

        with open("resp_emitidas.html", "w", encoding="utf-8") as f:
            f.write(resp_emitidas.text)
        # Falta verificar si se hizo el redireccionamiento de manera correcta
        return True


    def post_facturas_emitidas(self, fecha_inicial, fecha_final, estado="-1"):
        url = self.emitidas_url

        # ======================================================
        # 1️⃣ GET inicial
        # ======================================================
        r1 = self.session.get(url)
        with open("01_get_emitidas.html", "w", encoding="utf-8") as f:
            f.write(r1.text)
        soup = BeautifulSoup(r1.text, "html.parser")

        def get_hidden(name):
            tag = soup.find("input", {"name": name})
            return tag["value"] if tag else ""

        viewstate = get_hidden("__VIEWSTATE")
        viewstategenerator = get_hidden("__VIEWSTATEGENERATOR")
        eventvalidation = get_hidden("__EVENTVALIDATION")
        csrf = get_hidden("__CSRFTOKEN")

        # ======================================================
        # 2️⃣ POST seleccionar "Por Fechas"
        # ======================================================
        data_radio = {
            "ctl00$ScriptManager1":
                "ctl00$MainContent$UpnlBusqueda|ctl00$MainContent$RdoFechas",

            "__EVENTTARGET": "ctl00$MainContent$RdoFechas",
            "__EVENTARGUMENT": "",
            "__LASTFOCUS": "",

            "__VIEWSTATE": viewstate,
            "__VIEWSTATEGENERATOR": viewstategenerator,
            "__EVENTVALIDATION": eventvalidation,
            "__CSRFTOKEN": csrf,

            "ctl00$MainContent$FiltroCentral": "RdoFechas",

            "__ASYNCPOST": "true"
        }

        r2 = self.session.post(url, data=data_radio)
        with open("02_post_radio_raw.txt", "w", encoding="utf-8") as f:
            f.write(r2.text)

        # ======================================================
        # 2.1️⃣ Parsear respuesta parcial ASP.NET
        # ======================================================
        def parse_partial(text, field):
            for part in text.split("|"):
                if part.startswith(field):
                    return part.replace(field, "")
            return ""

        viewstate = parse_partial(r2.text, "__VIEWSTATE")
        eventvalidation = parse_partial(r2.text, "__EVENTVALIDATION")

        # ======================================================
        # 3️⃣ POST búsqueda real
        # ======================================================
        data_busqueda = {
            "ctl00$ScriptManager1":
                "ctl00$MainContent$UpnlBusqueda|ctl00$MainContent$BtnBusqueda",

            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "__LASTFOCUS": "",

            "__VIEWSTATE": viewstate,
            "__VIEWSTATEGENERATOR": viewstategenerator,
            "__EVENTVALIDATION": eventvalidation,
            "__CSRFTOKEN": csrf,

            "ctl00$MainContent$FiltroCentral": "RdoFechas",

            "ctl00$MainContent$CldFechaInicial2$Calendario_text": fecha_inicial,
            "ctl00$MainContent$CldFechaInicial2$DdlHora": "0",
            "ctl00$MainContent$CldFechaInicial2$DdlMinuto": "0",
            "ctl00$MainContent$CldFechaInicial2$DdlSegundo": "0",

            "ctl00$MainContent$CldFechaFinal2$Calendario_text": fecha_final,
            "ctl00$MainContent$CldFechaFinal2$DdlHora": "23",
            "ctl00$MainContent$CldFechaFinal2$DdlMinuto": "59",
            "ctl00$MainContent$CldFechaFinal2$DdlSegundo": "59",

            "ctl00$MainContent$DdlEstadoComprobante": estado,

            "__ASYNCPOST": "true",
            "ctl00$MainContent$BtnBusqueda": "Buscar CFDI"
        }

        r3 = self.session.post(url, data=data_busqueda)
        with open("03_post_busqueda_raw.txt", "w", encoding="utf-8") as f:
            f.write(r3.text)
        
        return r3




    def redirect_facturas_recibidas(self):
        """
        Realiza el direccionamiento a la pagina donde estan las facturas emitidas

        Returns:
            True si el redireccionamiento fue exitoso, False en caso contrario
        """
        resp_recibidas = self.session.get(self.recidas_url)

        with open("resp_recibidas.html", "w", encoding="utf-8") as f:
            f.write(resp_recibidas.text)
        # Falta verificar si se hizo el redireccionamiento de manera correcta
        return True

    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Realiza una petición GET usando la sesión autenticada.

        Args:
            url: URL a la que hacer la petición
            **kwargs: Argumentos adicionales para requests.get()

        Returns:
            Objeto Response de requests

        Raises:
            RuntimeError: Si no está autenticado

        Example:
            response = cliente.get('https://portalcfdi.../consulta')
            print(response.text)
        """
        if not self.is_authenticated:
            raise RuntimeError("Debe autenticarse primero usando login()")

        return self.session.get(url, **kwargs)


    def post(self, url: str, data=None, **kwargs) -> requests.Response:
        """
        Realiza una petición POST usando la sesión autenticada.

        Args:
            url: URL a la que hacer la petición
            data: Datos a enviar en el POST
            **kwargs: Argumentos adicionales para requests.post()

        Returns:
            Objeto Response de requests

        Raises:
            RuntimeError: Si no está autenticado

        Example:
            data = {'fecha_inicio': '2025-01-01', 'fecha_fin': '2025-01-31'}
            response = cliente.post('https://portalcfdi.../buscar', data=data)
        """
        if not self.is_authenticated:
            raise RuntimeError("Debe autenticarse primero usando login()")

        return self.session.post(url, data=data, **kwargs)


    def logout(self) -> bool:
        """
        Cierra la sesión actual.

        Returns:
            True si se cerró exitosamente

        Example:
            cliente.logout()
            print("Sesión cerrada")
        """
        # Nos vamos a la url de salida
        resp_logout = self.session.get(self.logout_url, headers=self.headers)
        # print(resp_logout.text)
        # Limpiar cookies
        self.session.cookies.clear()

        # Resetear estado
        self.is_authenticated = False
        self.user_info = {}
        self.current_url = None

        return True


    def get_user_info(self) -> Dict[str, str]:
        """
        Obtiene la información del usuario autenticado.

        Returns:
            Diccionario con los datos del usuario extraídos del token SAML

        Example:
            info = cliente.get_user_info()
            print(f"Nombre: {info.get('NombreUsuario')}")
            print(f"RFC: {info.get('IdUsuario')}")
            print(f"Tipo: {info.get('TipoContribuyente')}")
        """
        return self.user_info.copy()


    def is_session_active(self) -> bool:
        """
        Verifica si la sesión sigue activa.

        Returns:
            True si la sesión está activa, False en caso contrario

        Example:
            if not cliente.is_session_active():
                print("La sesión expiró, debe autenticarse nuevamente")
                cliente.login_interactive()
        """
        # Verificar si hay cookies de sesión
        if not self.is_authenticated:
            return False

        # Intentar acceder al portal
        try:
            resp = self.session.get(
                self.base_url,
                headers=self.headers,
                allow_redirects=False,
                timeout=10
            )

            # Si redirige al login, la sesión expiró
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "login" in location.lower() or "nidp" in location.lower():
                    self.is_authenticated = False
                    return False

            return True

        except Exception:
            return False


    def __repr__(self) -> str:
        """Representación en string del objeto."""
        status = "Autenticado" if self.is_authenticated else "No autenticado"
        user = self.user_info.get('NombreUsuario', 'N/A')
        return f"<SATPortalClient: {status}, Usuario: {user}>"


# =============================================================================
# EJEMPLO DE USO
# =============================================================================

if __name__ == "__main__":
    """
    Ejemplo de uso de la clase SATPortalClient.
    
    Puedes ejecutar este script directamente para probar la autenticación.
    """

    print("\n" + "="*70)
    print("  EJEMPLO DE USO - SATPortalClient")
    print("="*70)

    # Opción 1: Login interactivo (solicita datos al usuario)
    print("\n[Opción 1] Login interactivo\n")
    cliente = SATPortalClient()

    if cliente.login_interactive():
        print("\n✓ Login exitoso")

        # Obtener información del usuario
        info = cliente.get_user_info()
        print(f"\nInformación del usuario:")
        print(f"  • Nombre: {info.get('NombreUsuario')}")
        print(f"  • RFC: {info.get('IdUsuario')}")
        print(f"  • Tipo: {info.get('TipoContribuyente')}")

        # Verificar si la sesión está activa
        print(f"\n¿Sesión activa? {cliente.is_session_active()}")
        if cliente.is_session_active():
            # Nos dirigimos a la pagina que tiene las facturas emitidas
            if cliente.redirect_facturas_emitidas():
                # Realizamos la consulta de las facturas de x mes
                resp = cliente.post_facturas_emitidas(
                    # rfc=info.get('IdUsuario'),
                    fecha_inicial="01/01/2024",
                    fecha_final="31/01/2024"
                )

                print(resp.status_code)
                print(resp.url)
                print(resp.history)
            # Nos dirigimos a la pagina que contiene las facturas recibidas
            cliente.redirect_facturas_recibidas()

        # Ejemplo de uso de la sesión
        print("\n[*] Ejemplo de petición al portal:")
        print("    response = cliente.get('https://portalcfdi.../consulta')")

        # Cerrar sesión
        input("\nPresione ENTER para cerrar sesión...")
        cliente.logout()
        print("✓ Sesión cerrada")
    else:
        print("\n✗ Login fallido")


    # # Opción 2: Login programático (sin interacción)
    # print("\n" + "="*70)
    # print("\n[Opción 2] Login programático (comentado)\n")
    # print("# cliente2 = SATPortalClient()")
    # print("# cliente2.get_captcha()")
    # print("# # Ver captcha.jpg y obtener el código")
    # print("# if cliente2.login('XAXX010101000', 'password', 'ABC123'):")
    # print("#     print('Login exitoso')")
    # print("#     # Hacer operaciones...")
    # print("#     cliente2.logout()")

    # print("\n" + "="*70)