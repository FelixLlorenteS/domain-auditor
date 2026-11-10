/**
 * Second layer of the wiki: a plain-language "in a nutshell" for anyone, plus
 * quick-reference tables and common mistakes for technical readers.
 */
import type { Lang } from "../i18n";

type T = Record<Lang, string>;
type TList = Record<Lang, string[]>;

export interface WikiTable {
  cols: TList;
  rows: Record<Lang, string[][]>;
}

export interface WikiExtra {
  plain: T;
  tables?: WikiTable[];
  pitfalls?: TList;
}

export const EXTRA: Record<string, WikiExtra> = {
  "a-aaaa": {
    plain: {
      es: "Es la agenda de Internet: se escribe un nombre (`ejemplo.com`) y el DNS devuelve el «número de teléfono» del servidor, su dirección IP.",
      en: "It is the Internet's phone book: a name is typed (`example.com`) and DNS returns the server's \"phone number\", its IP address.",
    },
    pitfalls: {
      es: ["Olvidar el registro de `www` o de la raíz: la web funciona con uno y no con el otro.", "Dejar una IP antigua tras cambiar de hosting."],
      en: ["Forgetting the `www` or apex record: the site works with one and not the other.", "Leaving an old IP behind after changing hosting."],
    },
  },
  cname: {
    plain: {
      es: "Es un desvío: «para `www`, pregunta por `ejemplo.com`». Así, si cambia la dirección, sólo hay que actualizar un sitio.",
      en: "It is a redirect: \"for `www`, ask about `example.com`\". If the address changes, only one place needs updating.",
    },
    pitfalls: {
      es: ["Poner un CNAME en la raíz del dominio (algunos proveedores lo simulan con «CNAME flattening» o `ALIAS`).", "Añadir otros registros (TXT, MX) a un nombre que ya tiene CNAME."],
      en: ["Putting a CNAME at the domain apex (some providers emulate it with CNAME flattening or `ALIAS`).", "Adding other records (TXT, MX) to a name that already has a CNAME."],
    },
  },
  ns: {
    plain: {
      es: "Son los «dueños de la agenda» de un dominio: los servidores a los que el resto de Internet pregunta por sus registros. Se eligen en el registrador.",
      en: "They are a domain's \"phone book keepers\": the servers the rest of the Internet asks about its records. They are set at the registrar.",
    },
    pitfalls: {
      es: ["Cambiar los NS en el registrador sin haber copiado antes todos los registros al proveedor nuevo.", "Dejar NS de un proveedor antiguo que ya no responde."],
      en: ["Changing the NS at the registrar before copying every record to the new provider.", "Leaving NS of an old provider that no longer answers."],
    },
  },
  soa: {
    plain: {
      es: "Es la ficha técnica de una zona DNS: quién la gestiona y cada cuánto se sincronizan las copias. Normalmente la rellena el proveedor DNS y no hay que tocarla.",
      en: "It is a DNS zone's spec sheet: who manages it and how often copies sync. The DNS provider usually fills it in and it rarely needs touching.",
    },
    tables: [
      {
        cols: { es: ["Campo", "Significado"], en: ["Field", "Meaning"] },
        rows: {
          es: [
            ["MNAME", "Servidor primario de la zona"],
            ["RNAME", "Correo del responsable, con la `@` cambiada por un punto"],
            ["SERIAL", "Versión de la zona; debe crecer en cada cambio"],
            ["REFRESH", "Cada cuánto consultan los secundarios si hay cambios (s)"],
            ["RETRY", "Cuánto esperar para reintentar si falla (s)"],
            ["EXPIRE", "Cuándo dejan de responder los secundarios sin contacto (s)"],
            ["MINIMUM", "TTL de las respuestas negativas («no existe») (s)"],
          ],
          en: [
            ["MNAME", "Primary server of the zone"],
            ["RNAME", "Contact e-mail, with the `@` replaced by a dot"],
            ["SERIAL", "Zone version; must increase with every change"],
            ["REFRESH", "How often secondaries check for changes (s)"],
            ["RETRY", "How long to wait before retrying after a failure (s)"],
            ["EXPIRE", "When secondaries stop answering without contact (s)"],
            ["MINIMUM", "TTL of negative (\"does not exist\") answers (s)"],
          ],
        },
      },
    ],
  },
  txt: {
    plain: {
      es: "Es un tablón de notas públicas del dominio. Se usa para demostrar quién controla el dominio (Google, Microsoft…) y para las reglas del correo (SPF, DMARC, DKIM).",
      en: "It is the domain's public notice board. It is used to prove ownership of the domain (Google, Microsoft…) and for mail rules (SPF, DMARC, DKIM).",
    },
    pitfalls: {
      es: ["Crear un segundo TXT `v=spf1` en lugar de editar el existente.", "Pegar el valor con comillas extra o cortado a 255 caracteres."],
      en: ["Creating a second `v=spf1` TXT instead of editing the existing one.", "Pasting the value with extra quotes or cut at 255 characters."],
    },
  },
  rcode: {
    plain: {
      es: "Es la respuesta del DNS aunque no tenga datos: «existe pero no tiene eso», «no existe» o «no he podido averiguarlo».",
      en: "It is DNS's answer even when there is no data: \"exists but has none of that\", \"does not exist\" or \"could not find out\".",
    },
    tables: [
      {
        cols: { es: ["Código", "Nombre", "Significado"], en: ["Code", "Name", "Meaning"] },
        rows: {
          es: [
            ["0", "NOERROR", "Correcto (con o sin registros de ese tipo)"],
            ["2", "SERVFAIL", "El resolvedor no pudo obtener una respuesta fiable"],
            ["3", "NXDOMAIN", "El nombre no existe"],
            ["5", "REFUSED", "El servidor se niega a responder"],
          ],
          en: [
            ["0", "NOERROR", "Success (with or without records of that type)"],
            ["2", "SERVFAIL", "The resolver could not get a trustworthy answer"],
            ["3", "NXDOMAIN", "The name does not exist"],
            ["5", "REFUSED", "The server refuses to answer"],
          ],
        },
      },
    ],
  },
  dnssec: {
    plain: {
      es: "Es un sello de lacre para el DNS: cada respuesta va firmada, y quien la recibe comprueba que nadie la ha cambiado por el camino.",
      en: "It is a wax seal for DNS: every answer is signed, and whoever receives it checks nobody changed it on the way.",
    },
    tables: [
      {
        cols: { es: ["Registro", "Para qué sirve"], en: ["Record", "Purpose"] },
        rows: {
          es: [
            ["DNSKEY", "Claves públicas de la zona"],
            ["RRSIG", "Firma de cada conjunto de registros"],
            ["DS", "Resumen de la clave, publicado en la zona superior (el registrador)"],
            ["NSEC / NSEC3", "Prueba firmada de que un nombre no existe"],
            ["Bit AD", "Marca del resolvedor: «he validado esta respuesta»"],
          ],
          en: [
            ["DNSKEY", "Public keys of the zone"],
            ["RRSIG", "Signature of each record set"],
            ["DS", "Digest of the key, published in the parent zone (registrar)"],
            ["NSEC / NSEC3", "Signed proof that a name does not exist"],
            ["AD bit", "Resolver flag: \"I validated this answer\""],
          ],
        },
      },
    ],
    pitfalls: {
      es: ["Cambiar de proveedor DNS sin quitar o actualizar el DS: el dominio deja de resolver.", "Activarlo en el proveedor y olvidar publicar el DS en el registrador."],
      en: ["Changing DNS provider without removing or updating the DS: the domain stops resolving.", "Enabling it at the provider and forgetting to publish the DS at the registrar."],
    },
  },
  ct: {
    plain: {
      es: "Es un registro público de todas las llaves (certificados HTTPS) que se han hecho para un dominio. Cualquiera puede leerlo, así que muestra qué subdominios existen y quién hizo cada llave.",
      en: "It is a public record of every key (HTTPS certificate) ever made for a domain. Anyone can read it, so it shows which subdomains exist and who made each key.",
    },
    pitfalls: {
      es: ["Borrar un servicio en la nube (web, almacenamiento) y dejar su CNAME en el DNS: el subdominio queda disponible para otro.", "Creer que un subdominio «interno» es secreto: si tiene certificado público, aparece en Certificate Transparency."],
      en: ["Deleting a cloud service (site, storage) and leaving its CNAME in DNS: the subdomain is left up for grabs.", "Thinking an «internal» subdomain is secret: if it has a public certificate, it shows up in Certificate Transparency."],
    },
  },
  caa: {
    plain: {
      es: "Es la lista de cerrajeros autorizados a hacer copias de la llave de una web (el certificado HTTPS). Si alguien pide una copia a otro, se la deben negar.",
      en: "It is the list of locksmiths allowed to copy a website's key (the HTTPS certificate). If someone asks another one, they must refuse.",
    },
    tables: [
      {
        cols: { es: ["Etiqueta", "Ejemplo", "Significado"], en: ["Tag", "Example", "Meaning"] },
        rows: {
          es: [
            ["issue", "`0 issue \"letsencrypt.org\"`", "Puede emitir certificados normales"],
            ["issuewild", "`0 issuewild \";\"`", "Quién puede emitir comodines (`;` = nadie)"],
            ["iodef", "`0 iodef \"mailto:security@ejemplo.com\"`", "Dónde avisar de peticiones rechazadas"],
            ["flag 128", "`128 issue …`", "Crítico: una autoridad que no entienda la etiqueta no debe emitir"],
          ],
          en: [
            ["issue", "`0 issue \"letsencrypt.org\"`", "May issue regular certificates"],
            ["issuewild", "`0 issuewild \";\"`", "Who may issue wildcards (`;` = nobody)"],
            ["iodef", "`0 iodef \"mailto:security@example.com\"`", "Where to report refused requests"],
            ["flag 128", "`128 issue …`", "Critical: a CA that does not understand the tag must not issue"],
          ],
        },
      },
    ],
    pitfalls: {
      es: ["Poner una autoridad distinta a la que emite el certificado: la renovación falla.", "Olvidar que los subdominios heredan el CAA del dominio principal."],
      en: ["Listing an authority other than the one issuing the certificate: renewal fails.", "Forgetting that subdomains inherit the main domain's CAA."],
    },
  },
  mx: {
    plain: {
      es: "Es la dirección postal del correo de un dominio: dice a qué oficinas (servidores) hay que llevar las cartas para sus direcciones @.",
      en: "It is a domain's postal address for mail: it says which offices (servers) letters for its @ addresses go to.",
    },
    pitfalls: {
      es: ["Apuntar el MX a una IP o a un CNAME.", "Mezclar MX de dos proveedores: parte del correo llega a uno y parte al otro."],
      en: ["Pointing the MX to an IP or a CNAME.", "Mixing MX from two providers: some mail goes to one and some to the other."],
    },
  },
  spf: {
    plain: {
      es: "Es la lista de invitados del correo de un dominio: qué servidores pueden enviar mensajes en su nombre. Si llega un correo desde un servidor que no está en la lista, es sospechoso.",
      en: "It is a domain's guest list for mail: which servers may send messages on its behalf. A message from a server not on the list is suspicious.",
    },
    tables: [
      {
        cols: { es: ["Término", "Qué autoriza", "¿Gasta consulta?"], en: ["Term", "What it allows", "Costs a lookup?"] },
        rows: {
          es: [
            ["`ip4:192.0.2.0/24`", "Esa IP o rango IPv4", "No"],
            ["`ip6:2001:db8::/32`", "Esa IP o rango IPv6", "No"],
            ["`a`", "Las IP a las que apunta el dominio", "Sí"],
            ["`mx`", "Los servidores de correo entrante del dominio", "Sí"],
            ["`include:ejemplo.net`", "Lo que autorice el SPF de ese dominio", "Sí"],
            ["`exists:…`", "Uso avanzado: autoriza si ese nombre existe", "Sí"],
            ["`redirect=ejemplo.net`", "Usa el SPF de otro dominio", "Sí"],
            ["`-all` / `~all`", "Resto: rechazar / marcar como sospechoso", "No"],
            ["`?all` / `+all`", "Resto: no opinar / aceptar (no usar)", "No"],
          ],
          en: [
            ["`ip4:192.0.2.0/24`", "That IPv4 address or range", "No"],
            ["`ip6:2001:db8::/32`", "That IPv6 address or range", "No"],
            ["`a`", "The IPs the domain points to", "Yes"],
            ["`mx`", "The domain's inbound mail servers", "Yes"],
            ["`include:example.net`", "Whatever that domain's SPF allows", "Yes"],
            ["`exists:…`", "Advanced: allows if that name exists", "Yes"],
            ["`redirect=example.net`", "Uses another domain's SPF", "Yes"],
            ["`-all` / `~all`", "Everyone else: reject / flag as suspicious", "No"],
            ["`?all` / `+all`", "Everyone else: no opinion / accept (do not use)", "No"],
          ],
        },
      },
    ],
    pitfalls: {
      es: [
        "Tener dos registros SPF: se anulan los dos.",
        "Superar las 10 consultas al ir añadiendo servicios.",
        "Olvidar un servicio que envía en nombre del dominio (la web, el CRM, la facturación).",
      ],
      en: ["Having two SPF records: both are void.", "Going over 10 lookups as services are added.", "Forgetting a service that sends on behalf of the domain (website, CRM, invoicing)."],
    },
  },
  dkim: {
    plain: {
      es: "Es la firma y el sello de cada carta: el servidor firma el mensaje con una clave secreta y cualquiera puede comprobar la firma con la clave pública que el dominio publica en el DNS.",
      en: "It is each letter's signature and seal: the server signs the message with a secret key and anyone can check it with the public key the domain publishes in DNS.",
    },
    tables: [
      {
        cols: { es: ["Etiqueta", "Significado"], en: ["Tag", "Meaning"] },
        rows: {
          es: [
            ["`v=DKIM1`", "Versión (opcional, pero si está debe ir primero)"],
            ["`k=`", "Tipo de clave: `rsa` (por defecto) o `ed25519`"],
            ["`p=`", "Clave pública en base64; vacía = revocada"],
            ["`t=`", "`y` = modo prueba; `s` = sin subdominios"],
            ["`h=`", "Algoritmos de resumen aceptados"],
            ["`s=`", "Servicio (`email` o `*`)"],
          ],
          en: [
            ["`v=DKIM1`", "Version (optional, but first if present)"],
            ["`k=`", "Key type: `rsa` (default) or `ed25519`"],
            ["`p=`", "Base64 public key; empty = revoked"],
            ["`t=`", "`y` = test mode; `s` = no subdomains"],
            ["`h=`", "Accepted hash algorithms"],
            ["`s=`", "Service (`email` or `*`)"],
          ],
        },
      },
    ],
    pitfalls: {
      es: ["Activar DKIM en el proveedor pero no publicar la clave en el DNS (o al revés).", "Pegar una clave partida o con espacios.", "Seguir con claves de 1024 bits."],
      en: ["Enabling DKIM at the provider but not publishing the key in DNS (or vice versa).", "Pasting a broken key or one with spaces.", "Staying on 1024-bit keys."],
    },
  },
  dmarc: {
    plain: {
      es: "Es la norma de la casa: dice qué hacer con un correo que se hace pasar por el dominio (dejarlo pasar, mandarlo a spam o rechazarlo) y pide informes de quién lo intenta.",
      en: "It is the house rule: it says what to do with mail pretending to be the domain (let it through, send it to spam or reject it) and asks for reports on who tries.",
    },
    tables: [
      {
        cols: { es: ["Etiqueta", "Valores", "Significado"], en: ["Tag", "Values", "Meaning"] },
        rows: {
          es: [
            ["`v`", "`DMARC1`", "Versión; siempre la primera"],
            ["`p`", "`none` · `quarantine` · `reject`", "Política del dominio (si falta, `none`)"],
            ["`sp`", "igual que `p`", "Política de los subdominios"],
            ["`np`", "igual que `p`", "Política de subdominios que no existen"],
            ["`t`", "`y` · `n`", "Modo prueba: no aplicar la política"],
            ["`rua`", "`mailto:…`", "Dónde enviar informes agregados diarios"],
            ["`ruf`", "`mailto:…`", "Dónde enviar informes de fallos concretos"],
            ["`adkim` / `aspf`", "`r` · `s`", "Alineación relajada o estricta de DKIM / SPF"],
            ["`fo`", "`0` · `1` · `d` · `s`", "Cuándo generar informes de fallo"],
            ["`psd`", "`y` · `n` · `u`", "Si el dominio es un sufijo público"],
          ],
          en: [
            ["`v`", "`DMARC1`", "Version; always first"],
            ["`p`", "`none` · `quarantine` · `reject`", "Domain policy (`none` if missing)"],
            ["`sp`", "same as `p`", "Subdomain policy"],
            ["`np`", "same as `p`", "Policy for non-existent subdomains"],
            ["`t`", "`y` · `n`", "Test mode: do not apply the policy"],
            ["`rua`", "`mailto:…`", "Where to send daily aggregate reports"],
            ["`ruf`", "`mailto:…`", "Where to send individual failure reports"],
            ["`adkim` / `aspf`", "`r` · `s`", "Relaxed or strict DKIM / SPF alignment"],
            ["`fo`", "`0` · `1` · `d` · `s`", "When to generate failure reports"],
            ["`psd`", "`y` · `n` · `u`", "Whether the domain is a public suffix"],
          ],
        },
      },
    ],
    pitfalls: {
      es: [
        "Quedarse para siempre en `p=none`: no protege.",
        "Pasar a `reject` sin revisar los informes: se bloquea correo legítimo (facturas, formularios de la web).",
        "Poner en `rua` un buzón que no existe.",
      ],
      en: [
        "Staying on `p=none` forever: it does not protect.",
        "Moving to `reject` without reviewing reports: genuine mail gets blocked (invoices, website forms).",
        "Setting `rua` to a mailbox that does not exist.",
      ],
    },
  },
  "mta-sts": {
    plain: {
      es: "Es un cartel en la puerta del buzón que dice «sólo acepto cartas en sobre cerrado»: los demás servidores ya no pueden entregar correo al dominio sin cifrar.",
      en: "It is a sign on the mailbox saying \"sealed envelopes only\": other servers can no longer deliver mail to the domain unencrypted.",
    },
    tables: [
      {
        cols: { es: ["Línea del fichero", "Significado"], en: ["Policy line", "Meaning"] },
        rows: {
          es: [
            ["`version: STSv1`", "Versión, siempre esta"],
            ["`mode: enforce`", "`enforce` obliga; `testing` sólo informa; `none` desactiva"],
            ["`mx: mx1.ejemplo.com`", "Servidores permitidos; una línea por MX (admite `*.ejemplo.com`)"],
            ["`max_age: 604800`", "Segundos que se guarda la política (máx. 31557600)"],
          ],
          en: [
            ["`version: STSv1`", "Version, always this"],
            ["`mode: enforce`", "`enforce` requires; `testing` only reports; `none` disables"],
            ["`mx: mx1.example.com`", "Allowed servers; one line per MX (`*.example.com` allowed)"],
            ["`max_age: 604800`", "Seconds the policy is cached (max 31557600)"],
          ],
        },
      },
    ],
    pitfalls: {
      es: ["Cambiar el fichero sin cambiar el `id` del TXT: los remitentes siguen con la versión antigua.", "Olvidar un MX en la lista en modo `enforce`: el correo hacia él se rechaza."],
      en: ["Editing the file without changing the TXT `id`: senders keep the old version.", "Leaving an MX off the list in `enforce` mode: mail to it is refused."],
    },
  },
  "tls-rpt": {
    plain: {
      es: "Es el buzón de quejas del cifrado: si otro servidor no consigue entregar correo al dominio de forma segura, lo cuenta.",
      en: "It is the encryption complaints box: if another server cannot deliver mail to the domain securely, it reports it.",
    },
  },
  bimi: {
    plain: {
      es: "Es poner el logotipo de la marca en el sobre: los clientes de correo compatibles lo muestran junto a sus mensajes, pero sólo si el dominio demuestra que son suyos (DMARC aplicado).",
      en: "It is the brand's logo on the envelope: supporting mail clients show it next to its messages, but only if the domain proves they are its own (DMARC enforced).",
    },
  },
  ptr: {
    plain: {
      es: "Es la agenda al revés: dada una IP, dice cómo se llama. Los servidores de correo lo usan para comprobar que quien les escribe es quien dice ser.",
      en: "It is the phone book in reverse: given an IP, it tells its name. Mail servers use it to check the sender is who it claims to be.",
    },
    pitfalls: {
      es: ["Intentar crear el PTR en el proveedor DNS: lo gestiona quien asigna la IP.", "Dejar el nombre genérico del proveedor (`123-45-67-89.isp.net`) en un servidor de correo."],
      en: ["Trying to create the PTR at the DNS provider: whoever assigns the IP manages it.", "Keeping the provider's generic name (`123-45-67-89.isp.net`) on a mail server."],
    },
  },
  asn: {
    plain: {
      es: "Es saber a qué barrio (red) pertenece una dirección y quién es el dueño de ese barrio: un hosting, una CDN, una operadora…",
      en: "It is knowing which neighbourhood (network) an address belongs to and who owns it: a hosting provider, a CDN, an ISP…",
    },
  },
  intel: {
    plain: {
      es: "Es mirar el dominio con los ojos de quien lo vigila desde fuera: qué puertas tiene abiertas según un escáner público y si alguien lo ha señalado en un foro de seguridad.",
      en: "It is looking at the domain through the eyes of someone watching from outside: which doors a public scanner sees open and whether anyone has flagged it on a security forum.",
    },
    pitfalls: {
      es: ["Tomar una mención en OTX como prueba de que el dominio es malicioso.", "Dar por buenas las CVE de Shodan: las deduce de la versión anunciada y el servicio puede estar parcheado."],
      en: ["Taking a mention in OTX as proof that the domain is malicious.", "Trusting Shodan's CVEs as fact: it infers them from the announced version and the service may be patched."],
    },
  },
  rdap: {
    plain: {
      es: "Es el registro de la propiedad de Internet: quién tiene el dominio registrado, desde cuándo, hasta cuándo y si está protegido.",
      en: "It is the Internet's land registry: who holds the domain, since when, until when and whether it is protected.",
    },
    tables: [
      {
        cols: { es: ["Estado", "Significado"], en: ["Status", "Meaning"] },
        rows: {
          es: [
            ["`clientTransferProhibited`", "Bloqueo de transferencia puesto por el registrador"],
            ["`clientUpdateProhibited`", "No se pueden cambiar los datos (p. ej. los NS)"],
            ["`clientDeleteProhibited`", "No se puede borrar"],
            ["`server…Prohibited`", "Igual, pero impuesto por el registro del TLD"],
            ["`redemptionPeriod`", "Caducado: periodo de gracia para recuperarlo"],
            ["`pendingDelete`", "Se va a liberar; ya no se puede recuperar"],
          ],
          en: [
            ["`clientTransferProhibited`", "Transfer lock set by the registrar"],
            ["`clientUpdateProhibited`", "Data cannot be changed (e.g. NS)"],
            ["`clientDeleteProhibited`", "Cannot be deleted"],
            ["`server…Prohibited`", "Same, but set by the TLD registry"],
            ["`redemptionPeriod`", "Expired: grace period to recover it"],
            ["`pendingDelete`", "About to be released; can no longer be recovered"],
          ],
        },
      },
    ],
  },
  special: {
    plain: {
      es: "Son direcciones «de uso interno», como los números de extensión de una centralita: funcionan dentro de una red, pero no desde Internet.",
      en: "They are \"internal use\" addresses, like extension numbers on a switchboard: they work inside a network, not from the Internet.",
    },
    tables: [
      {
        cols: { es: ["Rango", "Uso"], en: ["Range", "Use"] },
        rows: {
          es: [
            ["`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`", "Redes privadas (RFC 1918)"],
            ["`100.64.0.0/10`", "CGNAT de operadoras (RFC 6598)"],
            ["`127.0.0.0/8`, `::1`", "El propio equipo (loopback)"],
            ["`169.254.0.0/16`, `fe80::/10`", "Enlace local (sin DHCP)"],
            ["`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`", "Documentación y ejemplos"],
            ["`fc00::/7`", "Redes privadas IPv6 (ULA)"],
          ],
          en: [
            ["`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`", "Private networks (RFC 1918)"],
            ["`100.64.0.0/10`", "Carrier-grade NAT (RFC 6598)"],
            ["`127.0.0.0/8`, `::1`", "The machine itself (loopback)"],
            ["`169.254.0.0/16`, `fe80::/10`", "Link-local (no DHCP)"],
            ["`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`", "Documentation and examples"],
            ["`fc00::/7`", "IPv6 private networks (ULA)"],
          ],
        },
      },
    ],
  },
  doh: {
    plain: {
      es: "En vez de preguntar al DNS por el canal normal, que un navegador no puede usar, la página pregunta por HTTPS a Cloudflare o Google, como quien consulta una web.",
      en: "Instead of asking DNS through the usual channel, which a browser cannot use, the page asks Cloudflare or Google over HTTPS, like visiting a website.",
    },
  },
  https: {
    plain: {
      es: "Es la diferencia entre una postal y un sobre cerrado. HSTS es la nota que deja la web en el navegador: «a partir de ahora, sólo en sobre cerrado».",
      en: "It is the difference between a postcard and a sealed envelope. HSTS is the note the site leaves in the browser: \"from now on, sealed envelopes only\".",
    },
    pitfalls: {
      es: ["Activar `includeSubDomains` con algún subdominio sin HTTPS: deja de abrirse.", "Redirigir HTTP a HTTPS sin HSTS: la primera petición sigue yendo sin cifrar."],
      en: ["Enabling `includeSubDomains` with a subdomain lacking HTTPS: it stops opening.", "Redirecting HTTP to HTTPS without HSTS: the first request still goes unencrypted."],
    },
  },
  tls: {
    plain: {
      es: "El certificado es el DNI de la web, firmado por una autoridad. TLS es el idioma del cifrado: las versiones antiguas tienen fallos conocidos.",
      en: "The certificate is the site's ID card, signed by an authority. TLS is the language of encryption: the old versions have known flaws.",
    },
    pitfalls: {
      es: ["Instalar sólo el certificado sin los intermedios: algunos navegadores y móviles no confían en él.", "Una renovación automática que falla en silencio hasta el día de la caducidad."],
      en: ["Installing only the certificate without the intermediates: some browsers and phones do not trust it.", "An automatic renewal failing silently until expiry day."],
    },
  },
  headers: {
    plain: {
      es: "Son las normas de la casa que la web entrega al navegador al llegar: «no me metas dentro de otra página», «no ejecutes lo que no sea código»…",
      en: "They are the house rules the site hands the browser on arrival: \"do not put me inside another page\", \"do not run what is not code\"…",
    },
  },
  "security-txt": {
    plain: {
      es: "Es el cartel de «en caso de avería, llame a…» de la web, para quien encuentre un fallo de seguridad.",
      en: "It is the site's \"in case of fault, call…\" sign, for whoever finds a security flaw.",
    },
  },
};
